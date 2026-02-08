// Package gigahost implements the libdns interfaces for the Gigahost DNS API (v0).
// See https://gigahost.no/api-dokumentasjon for API documentation.
package gigahost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// baseURL is the Gigahost API base URL. It is a var (not const) so that
// tests can point it at a local httptest server.
var baseURL = "https://api.gigahost.no/api/v0"

// Provider implements the libdns interfaces for Gigahost DNS.
type Provider struct {
	// Gigahost account username.
	Username string `json:"username,omitempty"`
	// Gigahost account password.
	Password string `json:"password,omitempty"`
	// Optional TOTP code for two-factor authentication.
	TOTPCode string `json:"totp_code,omitempty"`

	// internal state
	token      string
	tokenExp   time.Time
	mu         sync.Mutex
	httpClient *http.Client
}

// ---------- Gigahost API response/request types ----------

// apiMeta is the "meta" envelope returned by every Gigahost API response.
type apiMeta struct {
	Status        int    `json:"status"`
	StatusMessage string `json:"status_message"`
	Message       string `json:"message"`
}

// apiResponse is the generic envelope for all Gigahost API responses.
type apiResponse struct {
	Meta apiMeta         `json:"meta"`
	Data json.RawMessage `json:"data"`
}

// authRequest is the JSON body sent to POST /authenticate.
type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     int    `json:"code,omitempty"`
}

// authData is the "data" payload returned from POST /authenticate.
type authData struct {
	Token       string `json:"token"`
	TokenExpire int64  `json:"token_expire"`
	CustomerID  int    `json:"customer_id"`
}

// ghZone represents a zone object from GET /dns/zones.
type ghZone struct {
	ZoneID   int    `json:"zone_id"`
	ZoneName string `json:"zone_name"`
}

// ghRecord represents a DNS record from the Gigahost API.
type ghRecord struct {
	RecordID       string  `json:"record_id"`
	RecordName     string  `json:"record_name"`
	RecordType     string  `json:"record_type"`
	RecordValue    string  `json:"record_value"`
	RecordTTL      int     `json:"record_ttl"`
	RecordPriority *uint16 `json:"record_priority"`
}

// ghRecordRequest is the JSON body for creating or updating a record.
type ghRecordRequest struct {
	RecordName     string  `json:"record_name,omitempty"`
	RecordType     string  `json:"record_type,omitempty"`
	RecordValue    string  `json:"record_value"`
	RecordTTL      int     `json:"record_ttl,omitempty"`
	RecordPriority *uint16 `json:"record_priority,omitempty"`
}

// ---------- Authentication ----------

// authenticate obtains (or refreshes) a bearer token from the Gigahost API.
// The caller must hold p.mu.
func (p *Provider) authenticate(ctx context.Context) error {
	body := authRequest{
		Username: p.Username,
		Password: p.Password,
	}
	if p.TOTPCode != "" {
		code, err := strconv.Atoi(p.TOTPCode)
		if err != nil {
			return fmt.Errorf("gigahost: invalid TOTP code %q: %w", p.TOTPCode, err)
		}
		body.Code = code
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("gigahost: marshal auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/authenticate", bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("gigahost: create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client().Do(req)
	if err != nil {
		return fmt.Errorf("gigahost: auth request failed: %w", err)
	}
	defer resp.Body.Close()

	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("gigahost: decode auth response: %w", err)
	}
	if apiResp.Meta.Status != 200 {
		return fmt.Errorf("gigahost: auth failed: %s (status %d)", apiResp.Meta.Message, apiResp.Meta.Status)
	}

	var data authData
	if err := json.Unmarshal(apiResp.Data, &data); err != nil {
		return fmt.Errorf("gigahost: decode auth data: %w", err)
	}

	p.token = data.Token
	p.tokenExp = time.Unix(data.TokenExpire, 0)
	return nil
}

// ensureAuth makes sure we have a valid, non-expired token.
// The caller must hold p.mu.
func (p *Provider) ensureAuth(ctx context.Context) error {
	// Re-authenticate if we have no token or it expires within 30 seconds.
	if p.token == "" || time.Now().After(p.tokenExp.Add(-30*time.Second)) {
		return p.authenticate(ctx)
	}
	return nil
}

// client returns the HTTP client, initialising a default one if needed.
func (p *Provider) client() *http.Client {
	if p.httpClient == nil {
		p.httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return p.httpClient
}

// ---------- API helpers ----------

// doRequest performs an authenticated HTTP request and decodes the response envelope.
// The caller must hold p.mu (so the token is stable).
func (p *Provider) doRequest(ctx context.Context, method, url string, body interface{}) (*apiResponse, error) {
	if err := p.ensureAuth(ctx); err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("gigahost: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("gigahost: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("gigahost: request %s %s failed: %w", method, url, err)
	}
	defer resp.Body.Close()

	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("gigahost: decode response from %s %s: %w", method, url, err)
	}

	// Treat any non-2xx meta status as an error.
	if apiResp.Meta.Status < 200 || apiResp.Meta.Status >= 300 {
		return nil, fmt.Errorf("gigahost: API error from %s %s: %s (status %d)",
			method, url, apiResp.Meta.Message, apiResp.Meta.Status)
	}

	return &apiResp, nil
}

// ---------- Zone resolution ----------

// getZoneID finds the zone_id for the given zone name by listing all zones.
// The zone parameter is an FQDN with trailing dot (e.g. "example.com.").
func (p *Provider) getZoneID(ctx context.Context, zone string) (int, error) {
	zoneName := strings.TrimSuffix(zone, ".")

	apiResp, err := p.doRequest(ctx, http.MethodGet, baseURL+"/dns/zones", nil)
	if err != nil {
		return 0, fmt.Errorf("gigahost: list zones: %w", err)
	}

	var zones []ghZone
	if err := json.Unmarshal(apiResp.Data, &zones); err != nil {
		return 0, fmt.Errorf("gigahost: decode zones: %w", err)
	}

	for _, z := range zones {
		if strings.EqualFold(z.ZoneName, zoneName) {
			return z.ZoneID, nil
		}
	}

	return 0, fmt.Errorf("gigahost: zone %q not found", zoneName)
}

// ---------- Record fetching ----------

// fetchRecords retrieves all DNS records for the given zone ID.
func (p *Provider) fetchRecords(ctx context.Context, zoneID int) ([]ghRecord, error) {
	url := fmt.Sprintf("%s/dns/zones/%d/records", baseURL, zoneID)
	apiResp, err := p.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	var records []ghRecord
	if err := json.Unmarshal(apiResp.Data, &records); err != nil {
		return nil, fmt.Errorf("gigahost: decode records: %w", err)
	}

	return records, nil
}

// ---------- Record conversion ----------

// toLibdnsRecord converts a Gigahost API record to a libdns Record.
// It returns typed records (Address, TXT, CNAME, MX, NS) where possible,
// falling back to RR for other types.
func toLibdnsRecord(rec ghRecord, zone string) (libdns.Record, error) {
	name := ghNameToLibdns(rec.RecordName)
	ttl := time.Duration(rec.RecordTTL) * time.Second

	switch rec.RecordType {
	case "A", "AAAA":
		addr, err := netip.ParseAddr(rec.RecordValue)
		if err != nil {
			return libdns.RR{
				Name: name,
				TTL:  ttl,
				Type: rec.RecordType,
				Data: rec.RecordValue,
			}, nil
		}
		return libdns.Address{
			Name: name,
			TTL:  ttl,
			IP:   addr,
		}, nil

	case "CNAME":
		return libdns.CNAME{
			Name:   name,
			TTL:    ttl,
			Target: ensureTrailingDot(rec.RecordValue),
		}, nil

	case "MX":
		var pref uint16
		if rec.RecordPriority != nil {
			pref = *rec.RecordPriority
		}
		return libdns.MX{
			Name:       name,
			TTL:        ttl,
			Preference: pref,
			Target:     ensureTrailingDot(rec.RecordValue),
		}, nil

	case "NS":
		return libdns.NS{
			Name:   name,
			TTL:    ttl,
			Target: ensureTrailingDot(rec.RecordValue),
		}, nil

	case "TXT":
		return libdns.TXT{
			Name: name,
			TTL:  ttl,
			Text: rec.RecordValue,
		}, nil

	default:
		// For SRV, CAA, and any other types, use the generic RR and let
		// libdns parse it into the appropriate typed struct.
		rr := libdns.RR{
			Name: name,
			TTL:  ttl,
			Type: rec.RecordType,
			Data: rec.RecordValue,
		}
		parsed, err := rr.Parse()
		if err != nil {
			// If parsing fails, return the raw RR.
			return rr, nil
		}
		return parsed, nil
	}
}

// toGhRecordRequest converts a libdns Record into a Gigahost API record request.
func toGhRecordRequest(rec libdns.Record) ghRecordRequest {
	rr := rec.RR()
	ghReq := ghRecordRequest{
		RecordName:  libdnsNameToGh(rr.Name),
		RecordType:  rr.Type,
		RecordValue: rr.Data,
		RecordTTL:   int(rr.TTL.Seconds()),
	}

	// For MX records, extract the priority from the typed record.
	if mx, ok := rec.(libdns.MX); ok {
		pref := mx.Preference
		ghReq.RecordPriority = &pref
		// MX data from RR() is "preference target" — we only want the target as the value.
		ghReq.RecordValue = strings.TrimSuffix(mx.Target, ".")
	}

	// Strip trailing dots from CNAME and NS targets for the Gigahost API.
	if rr.Type == "CNAME" || rr.Type == "NS" {
		ghReq.RecordValue = strings.TrimSuffix(ghReq.RecordValue, ".")
	}

	return ghReq
}

// ---------- Name helpers ----------

// ghNameToLibdns converts a Gigahost record name to a libdns relative name.
// Gigahost uses "@" for the zone apex; libdns also uses "@".
func ghNameToLibdns(name string) string {
	if name == "" {
		return "@"
	}
	return name
}

// libdnsNameToGh converts a libdns relative name to a Gigahost record name.
func libdnsNameToGh(name string) string {
	if name == "" || name == "@" {
		return "@"
	}
	return name
}

// ensureTrailingDot adds a trailing dot to a hostname if not already present.
func ensureTrailingDot(s string) string {
	if s != "" && !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

// ---------- Record matching helpers ----------

// recordMatchesNameType checks if a Gigahost record matches the given libdns record
// by name and type.
func recordMatchesNameType(ghRec ghRecord, libRec libdns.Record) bool {
	rr := libRec.RR()
	return strings.EqualFold(ghRec.RecordName, libdnsNameToGh(rr.Name)) &&
		strings.EqualFold(ghRec.RecordType, rr.Type)
}

// recordMatchesNameTypeValue checks if a Gigahost record matches the given libdns record
// by name, type, and value.
func recordMatchesNameTypeValue(ghRec ghRecord, libRec libdns.Record) bool {
	if !recordMatchesNameType(ghRec, libRec) {
		return false
	}
	rr := libRec.RR()
	// Normalize values for comparison: strip trailing dots.
	ghVal := strings.TrimSuffix(ghRec.RecordValue, ".")
	libVal := strings.TrimSuffix(rr.Data, ".")

	// For MX records, the RR data includes priority prefix — compare just the target.
	if strings.EqualFold(rr.Type, "MX") {
		if mx, ok := libRec.(libdns.MX); ok {
			libVal = strings.TrimSuffix(mx.Target, ".")
		}
	}

	return strings.EqualFold(ghVal, libVal)
}

// ---------- libdns interface implementations ----------

// GetRecords returns all the records in the DNS zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	ghRecords, err := p.fetchRecords(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	records := make([]libdns.Record, 0, len(ghRecords))
	for _, rec := range ghRecords {
		libRec, err := toLibdnsRecord(rec, zone)
		if err != nil {
			return nil, fmt.Errorf("gigahost: converting record %+v: %w", rec, err)
		}
		records = append(records, libRec)
	}

	return records, nil
}

// AppendRecords creates the given records in the zone. It returns the records
// that were created, with their IDs populated.
//
// Because the Gigahost API does not return the record_id on creation, we
// re-fetch all records after creating and match by name+type+value to find
// the newly created records.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Create each record.
	for _, rec := range recs {
		ghReq := toGhRecordRequest(rec)
		url := fmt.Sprintf("%s/dns/zones/%d/records", baseURL, zoneID)
		_, err := p.doRequest(ctx, http.MethodPost, url, ghReq)
		if err != nil {
			return nil, fmt.Errorf("gigahost: create record %+v: %w", rec.RR(), err)
		}
	}

	// Re-fetch all records to get the IDs of the newly created ones.
	allRecords, err := p.fetchRecords(ctx, zoneID)
	if err != nil {
		return nil, fmt.Errorf("gigahost: re-fetch records after create: %w", err)
	}

	// Match each input record to a fetched record by name+type+value.
	var created []libdns.Record
	for _, rec := range recs {
		for _, ghRec := range allRecords {
			if recordMatchesNameTypeValue(ghRec, rec) {
				libRec, err := toLibdnsRecord(ghRec, zone)
				if err != nil {
					return nil, fmt.Errorf("gigahost: converting record %+v: %w", ghRec, err)
				}
				created = append(created, libRec)
				break
			}
		}
	}

	return created, nil
}

// SetRecords sets the given records in the zone, creating or updating as needed.
// For each input record: if a record with the same name and type exists, it is
// updated; otherwise a new record is created.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Fetch existing records to determine which ones to update vs create.
	existing, err := p.fetchRecords(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	var results []libdns.Record
	var needsRefetch bool

	for _, rec := range recs {
		ghReq := toGhRecordRequest(rec)

		// Find an existing record with the same name and type.
		var match *ghRecord
		for i := range existing {
			if recordMatchesNameType(existing[i], rec) {
				match = &existing[i]
				break
			}
		}

		if match != nil {
			// Update existing record.
			url := fmt.Sprintf("%s/dns/zones/%d/records/%s", baseURL, zoneID, match.RecordID)
			apiResp, err := p.doRequest(ctx, http.MethodPut, url, ghReq)
			if err != nil {
				return nil, fmt.Errorf("gigahost: update record %s: %w", match.RecordID, err)
			}

			// Try to decode the updated record from the response.
			var updatedRec ghRecord
			if err := json.Unmarshal(apiResp.Data, &updatedRec); err == nil && updatedRec.RecordID != "" {
				libRec, err := toLibdnsRecord(updatedRec, zone)
				if err != nil {
					return nil, fmt.Errorf("gigahost: converting updated record: %w", err)
				}
				results = append(results, libRec)
			} else {
				// If the API doesn't return the full record, construct it from what we know.
				updatedGh := ghRecord{
					RecordID:       match.RecordID,
					RecordName:     ghReq.RecordName,
					RecordType:     ghReq.RecordType,
					RecordValue:    ghReq.RecordValue,
					RecordTTL:      ghReq.RecordTTL,
					RecordPriority: ghReq.RecordPriority,
				}
				libRec, err := toLibdnsRecord(updatedGh, zone)
				if err != nil {
					return nil, fmt.Errorf("gigahost: converting updated record: %w", err)
				}
				results = append(results, libRec)
			}
		} else {
			// Create new record. POST doesn't return the ID, so we'll need to re-fetch.
			url := fmt.Sprintf("%s/dns/zones/%d/records", baseURL, zoneID)
			_, err := p.doRequest(ctx, http.MethodPost, url, ghReq)
			if err != nil {
				return nil, fmt.Errorf("gigahost: create record %+v: %w", rec.RR(), err)
			}
			needsRefetch = true
		}
	}

	// If we created any new records, re-fetch to get their IDs.
	if needsRefetch {
		allRecords, err := p.fetchRecords(ctx, zoneID)
		if err != nil {
			return nil, fmt.Errorf("gigahost: re-fetch records after set: %w", err)
		}

		for _, rec := range recs {
			// Skip records that were updated (already in results).
			alreadyHandled := false
			for _, existing := range existing {
				if recordMatchesNameType(existing, rec) {
					alreadyHandled = true
					break
				}
			}
			if alreadyHandled {
				continue
			}

			// Find the newly created record.
			for _, ghRec := range allRecords {
				if recordMatchesNameTypeValue(ghRec, rec) {
					libRec, err := toLibdnsRecord(ghRec, zone)
					if err != nil {
						return nil, fmt.Errorf("gigahost: converting record: %w", err)
					}
					results = append(results, libRec)
					break
				}
			}
		}
	}

	return results, nil
}

// DeleteRecords deletes the given records from the zone. If a record's ID is
// not set, it will be looked up by name and type. It returns the records that
// were successfully deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Fetch all records upfront — we need record IDs for deletion
	// and name/type for the required query parameters.
	existing, err := p.fetchRecords(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	var deleted []libdns.Record

	for _, rec := range recs {
		rr := rec.RR()

		// Find matching records in the zone.
		var matches []ghRecord
		for _, ghRec := range existing {
			if matchesForDeletion(ghRec, rec) {
				matches = append(matches, ghRec)
			}
		}

		if len(matches) == 0 {
			// Record not found — silently skip per libdns contract.
			continue
		}

		for _, match := range matches {
			// Build the DELETE URL with required query parameters.
			deleteURL := fmt.Sprintf("%s/dns/zones/%d/records/%s?name=%s&type=%s",
				baseURL, zoneID, match.RecordID,
				match.RecordName, match.RecordType)

			_, err := p.doRequest(ctx, http.MethodDelete, deleteURL, nil)
			if err != nil {
				return nil, fmt.Errorf("gigahost: delete record %s (name=%s, type=%s): %w",
					match.RecordID, rr.Name, rr.Type, err)
			}

			libRec, err := toLibdnsRecord(match, zone)
			if err != nil {
				return nil, fmt.Errorf("gigahost: converting deleted record: %w", err)
			}
			deleted = append(deleted, libRec)
		}
	}

	return deleted, nil
}

// matchesForDeletion checks if a Gigahost record matches a libdns record for
// deletion purposes. Per the libdns contract, if Type, TTL, or Value are empty/zero,
// they act as wildcards. Name must always be specified.
func matchesForDeletion(ghRec ghRecord, libRec libdns.Record) bool {
	rr := libRec.RR()

	// Name must always match.
	if !strings.EqualFold(ghRec.RecordName, libdnsNameToGh(rr.Name)) {
		return false
	}

	// If type is specified, it must match.
	if rr.Type != "" && !strings.EqualFold(ghRec.RecordType, rr.Type) {
		return false
	}

	// If TTL is specified, it must match.
	if rr.TTL != 0 && ghRec.RecordTTL != int(rr.TTL.Seconds()) {
		return false
	}

	// If value/data is specified, it must match.
	if rr.Data != "" {
		ghVal := strings.TrimSuffix(ghRec.RecordValue, ".")
		libVal := strings.TrimSuffix(rr.Data, ".")

		// For MX records, the RR data includes priority prefix.
		if strings.EqualFold(rr.Type, "MX") {
			if mx, ok := libRec.(libdns.MX); ok {
				libVal = strings.TrimSuffix(mx.Target, ".")
			}
		}

		if !strings.EqualFold(ghVal, libVal) {
			return false
		}
	}

	return true
}

// Interface guards.
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
