package gigahost

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// ---------- Test data ----------

const testZone = "example.no."
const testZoneName = "example.no"
const testZoneID = "42"

// testRecords returns a realistic set of DNS records for the test zone.
func testRecords() []ghRecord {
	mx10 := flexUint16(10)
	return []ghRecord{
		{RecordID: "101", RecordName: "www", RecordType: "A", RecordValue: "93.184.216.34", RecordTTL: 3600},
		{RecordID: "102", RecordName: "@", RecordType: "AAAA", RecordValue: "2001:db8::1", RecordTTL: 3600},
		{RecordID: "103", RecordName: "mail", RecordType: "CNAME", RecordValue: "mail.example.no", RecordTTL: 3600},
		{RecordID: "104", RecordName: "@", RecordType: "MX", RecordValue: "mail.example.no", RecordTTL: 3600, RecordPriority: &mx10},
		{RecordID: "105", RecordName: "_acme-challenge", RecordType: "TXT", RecordValue: "test-challenge-token", RecordTTL: 120},
	}
}

// ---------- Mock server ----------

// mockState holds mutable state for the mock API server.
type mockState struct {
	mu      sync.Mutex
	records []ghRecord
	nextID  int
}

func newMockState() *mockState {
	recs := testRecords()
	return &mockState{
		records: recs,
		nextID:  200,
	}
}

// setupTestServer creates an httptest.Server that simulates the Gigahost API
// and returns a Provider configured to use it.
func setupTestServer(t *testing.T) (*httptest.Server, *Provider, *mockState) {
	t.Helper()

	state := newMockState()
	mux := http.NewServeMux()

	// POST /api/v0/authenticate
	mux.HandleFunc("POST /api/v0/authenticate", func(w http.ResponseWriter, r *http.Request) {
		var req authRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIResponse(w, 400, "bad request", nil)
			return
		}
		if req.Username != "testuser" || req.Password != "testpass" {
			writeAPIResponse(w, 403, "invalid credentials", nil)
			return
		}
		data := authData{
			Token:       "test-token-abc123",
			TokenExpire: time.Now().Add(1 * time.Hour).Unix(),
			CustomerID:  json.RawMessage(`1`),
		}
		writeAPIResponse(w, 200, "ok", data)
	})

	// GET /api/v0/dns/zones
	mux.HandleFunc("GET /api/v0/dns/zones", func(w http.ResponseWriter, r *http.Request) {
		zones := []ghZone{
			{ZoneID: json.Number(testZoneID), ZoneName: testZoneName},
			{ZoneID: json.Number("99"), ZoneName: "other.no"},
		}
		writeAPIResponse(w, 200, "ok", zones)
	})

	// GET /api/v0/dns/zones/{id}/records
	mux.HandleFunc("GET /api/v0/dns/zones/{id}/records", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id != testZoneID {
			writeAPIResponse(w, 404, "zone not found", nil)
			return
		}
		state.mu.Lock()
		recs := make([]ghRecord, len(state.records))
		copy(recs, state.records)
		state.mu.Unlock()
		writeAPIResponse(w, 200, "ok", recs)
	})

	// POST /api/v0/dns/zones/{id}/records
	mux.HandleFunc("POST /api/v0/dns/zones/{id}/records", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id != testZoneID {
			writeAPIResponse(w, 404, "zone not found", nil)
			return
		}
		var req ghRecordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIResponse(w, 400, "bad request", nil)
			return
		}
		state.mu.Lock()
		var prio *flexUint16
		if req.RecordPriority != nil {
			v := flexUint16(*req.RecordPriority)
			prio = &v
		}
		newRec := ghRecord{
			RecordID:       fmt.Sprintf("%d", state.nextID),
			RecordName:     req.RecordName,
			RecordType:     req.RecordType,
			RecordValue:    req.RecordValue,
			RecordTTL:      req.RecordTTL,
			RecordPriority: prio,
		}
		state.nextID++
		state.records = append(state.records, newRec)
		state.mu.Unlock()
		// Gigahost returns 201 with no record_id in the body.
		writeAPIResponse(w, 201, "created", nil)
	})

	// PUT /api/v0/dns/zones/{id}/records/{record_id}
	mux.HandleFunc("PUT /api/v0/dns/zones/{id}/records/{record_id}", func(w http.ResponseWriter, r *http.Request) {
		zoneIDStr := r.PathValue("id")
		recordID := r.PathValue("record_id")
		if zoneIDStr != testZoneID {
			writeAPIResponse(w, 404, "zone not found", nil)
			return
		}
		var req ghRecordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIResponse(w, 400, "bad request", nil)
			return
		}
		state.mu.Lock()
		var updated *ghRecord
		for i := range state.records {
			if state.records[i].RecordID == recordID {
				state.records[i].RecordValue = req.RecordValue
				state.records[i].RecordTTL = req.RecordTTL
				if req.RecordPriority != nil {
					v := flexUint16(*req.RecordPriority)
					state.records[i].RecordPriority = &v
				}
				updated = &state.records[i]
				break
			}
		}
		state.mu.Unlock()
		if updated == nil {
			writeAPIResponse(w, 404, "record not found", nil)
			return
		}
		writeAPIResponse(w, 200, "ok", updated)
	})

	// DELETE /api/v0/dns/zones/{id}/records/{record_id}
	mux.HandleFunc("DELETE /api/v0/dns/zones/{id}/records/{record_id}", func(w http.ResponseWriter, r *http.Request) {
		zoneIDStr := r.PathValue("id")
		recordID := r.PathValue("record_id")
		if zoneIDStr != testZoneID {
			writeAPIResponse(w, 404, "zone not found", nil)
			return
		}
		state.mu.Lock()
		found := false
		for i := range state.records {
			if state.records[i].RecordID == recordID {
				state.records = append(state.records[:i], state.records[i+1:]...)
				found = true
				break
			}
		}
		state.mu.Unlock()
		if !found {
			writeAPIResponse(w, 404, "record not found", nil)
			return
		}
		writeAPIResponse(w, 200, "deleted", nil)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	provider := &Provider{
		Username:   "testuser",
		Password:   "testpass",
		httpClient: server.Client(),
	}

	// Override the package-level baseURL to point at the test server.
	origBaseURL := baseURL
	baseURL = server.URL + "/api/v0"
	t.Cleanup(func() { baseURL = origBaseURL })

	return server, provider, state
}

// writeAPIResponse writes a Gigahost-style API response envelope.
func writeAPIResponse(w http.ResponseWriter, status int, message string, data interface{}) {
	resp := apiResponse{
		Meta: apiMeta{
			Status:  status,
			Message: message,
		},
	}
	if data != nil {
		raw, _ := json.Marshal(data)
		resp.Data = raw
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // HTTP status is always 200; the API status is in the envelope.
	json.NewEncoder(w).Encode(resp)
}

// ---------- Authentication tests ----------

func TestAuthenticate(t *testing.T) {
	_, p, _ := setupTestServer(t)
	ctx := context.Background()

	p.mu.Lock()
	err := p.authenticate(ctx)
	p.mu.Unlock()

	if err != nil {
		t.Fatalf("authenticate() error: %v", err)
	}
	if p.token != "test-token-abc123" {
		t.Errorf("expected token %q, got %q", "test-token-abc123", p.token)
	}
	if p.tokenExp.IsZero() {
		t.Error("expected tokenExp to be set")
	}
}

func TestAuthenticateWithTOTP(t *testing.T) {
	state := newMockState()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v0/authenticate", func(w http.ResponseWriter, r *http.Request) {
		var req authRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIResponse(w, 400, "bad request", nil)
			return
		}
		if req.Username != "testuser" || req.Password != "testpass" || req.Code != 123456 {
			writeAPIResponse(w, 403, "invalid credentials or TOTP", nil)
			return
		}
		data := authData{
			Token:       "totp-token-xyz",
			TokenExpire: time.Now().Add(1 * time.Hour).Unix(),
			CustomerID:  json.RawMessage(`1`),
		}
		writeAPIResponse(w, 200, "ok", data)
	})

	_ = state // state not needed for auth-only test
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	origBaseURL := baseURL
	baseURL = server.URL + "/api/v0"
	t.Cleanup(func() { baseURL = origBaseURL })

	p := &Provider{
		Username:   "testuser",
		Password:   "testpass",
		TOTPCode:   "123456",
		httpClient: server.Client(),
	}

	ctx := context.Background()
	p.mu.Lock()
	err := p.authenticate(ctx)
	p.mu.Unlock()

	if err != nil {
		t.Fatalf("authenticate() with TOTP error: %v", err)
	}
	if p.token != "totp-token-xyz" {
		t.Errorf("expected token %q, got %q", "totp-token-xyz", p.token)
	}
}

func TestAuthenticateFailure(t *testing.T) {
	_, p, _ := setupTestServer(t)
	p.Username = "wronguser"
	p.Password = "wrongpass"

	ctx := context.Background()
	p.mu.Lock()
	err := p.authenticate(ctx)
	p.mu.Unlock()

	if err == nil {
		t.Fatal("expected error for invalid credentials, got nil")
	}
	if p.token != "" {
		t.Errorf("expected empty token after failed auth, got %q", p.token)
	}
}

func TestTokenReuse(t *testing.T) {
	_, p, _ := setupTestServer(t)
	ctx := context.Background()

	// First auth.
	p.mu.Lock()
	err := p.ensureAuth(ctx)
	p.mu.Unlock()
	if err != nil {
		t.Fatalf("first ensureAuth() error: %v", err)
	}
	firstToken := p.token
	firstExp := p.tokenExp

	// Second call should reuse the token (not expired).
	p.mu.Lock()
	err = p.ensureAuth(ctx)
	p.mu.Unlock()
	if err != nil {
		t.Fatalf("second ensureAuth() error: %v", err)
	}
	if p.token != firstToken {
		t.Errorf("expected token to be reused, got different token")
	}
	if !p.tokenExp.Equal(firstExp) {
		t.Errorf("expected tokenExp to be unchanged")
	}
}

func TestTokenRefresh(t *testing.T) {
	_, p, _ := setupTestServer(t)
	ctx := context.Background()

	// First auth.
	p.mu.Lock()
	err := p.ensureAuth(ctx)
	p.mu.Unlock()
	if err != nil {
		t.Fatalf("first ensureAuth() error: %v", err)
	}

	// Simulate an expired token by setting tokenExp to the past.
	p.mu.Lock()
	p.tokenExp = time.Now().Add(-1 * time.Minute)
	p.mu.Unlock()

	// ensureAuth should re-authenticate.
	p.mu.Lock()
	err = p.ensureAuth(ctx)
	p.mu.Unlock()
	if err != nil {
		t.Fatalf("ensureAuth() after expiry error: %v", err)
	}
	if p.token == "" {
		t.Error("expected token to be refreshed, got empty")
	}
	if !p.tokenExp.After(time.Now()) {
		t.Error("expected tokenExp to be in the future after refresh")
	}
}

// ---------- GetRecords tests ----------

func TestGetRecords(t *testing.T) {
	_, p, _ := setupTestServer(t)
	ctx := context.Background()

	records, err := p.GetRecords(ctx, testZone)
	if err != nil {
		t.Fatalf("GetRecords() error: %v", err)
	}

	if len(records) != 5 {
		t.Fatalf("expected 5 records, got %d", len(records))
	}

	// Verify the A record.
	found := false
	for _, rec := range records {
		rr := rec.RR()
		if rr.Type == "A" && rr.Name == "www" {
			found = true
			addr, ok := rec.(libdns.Address)
			if !ok {
				t.Errorf("expected A record to be libdns.Address, got %T", rec)
				break
			}
			expectedIP := netip.MustParseAddr("93.184.216.34")
			if addr.IP != expectedIP {
				t.Errorf("expected IP %s, got %s", expectedIP, addr.IP)
			}
			if rr.TTL != 3600*time.Second {
				t.Errorf("expected TTL 3600s, got %s", rr.TTL)
			}
			break
		}
	}
	if !found {
		t.Error("A record for 'www' not found in results")
	}

	// Verify the MX record.
	found = false
	for _, rec := range records {
		rr := rec.RR()
		if rr.Type == "MX" {
			found = true
			mx, ok := rec.(libdns.MX)
			if !ok {
				t.Errorf("expected MX record to be libdns.MX, got %T", rec)
				break
			}
			if mx.Preference != 10 {
				t.Errorf("expected MX preference 10, got %d", mx.Preference)
			}
			if mx.Target != "mail.example.no." {
				t.Errorf("expected MX target %q, got %q", "mail.example.no.", mx.Target)
			}
			break
		}
	}
	if !found {
		t.Error("MX record not found in results")
	}

	// Verify the TXT record.
	found = false
	for _, rec := range records {
		rr := rec.RR()
		if rr.Type == "TXT" {
			found = true
			txt, ok := rec.(libdns.TXT)
			if !ok {
				t.Errorf("expected TXT record to be libdns.TXT, got %T", rec)
				break
			}
			if txt.Text != "test-challenge-token" {
				t.Errorf("expected TXT text %q, got %q", "test-challenge-token", txt.Text)
			}
			break
		}
	}
	if !found {
		t.Error("TXT record not found in results")
	}

	// Verify the CNAME record.
	found = false
	for _, rec := range records {
		rr := rec.RR()
		if rr.Type == "CNAME" {
			found = true
			cname, ok := rec.(libdns.CNAME)
			if !ok {
				t.Errorf("expected CNAME record to be libdns.CNAME, got %T", rec)
				break
			}
			if cname.Target != "mail.example.no." {
				t.Errorf("expected CNAME target %q, got %q", "mail.example.no.", cname.Target)
			}
			break
		}
	}
	if !found {
		t.Error("CNAME record not found in results")
	}

	// Verify the AAAA record.
	found = false
	for _, rec := range records {
		rr := rec.RR()
		if rr.Type == "AAAA" && rr.Name == "@" {
			found = true
			addr, ok := rec.(libdns.Address)
			if !ok {
				t.Errorf("expected AAAA record to be libdns.Address, got %T", rec)
				break
			}
			expectedIP := netip.MustParseAddr("2001:db8::1")
			if addr.IP != expectedIP {
				t.Errorf("expected IP %s, got %s", expectedIP, addr.IP)
			}
			break
		}
	}
	if !found {
		t.Error("AAAA record for '@' not found in results")
	}
}

func TestGetRecordsEmptyZone(t *testing.T) {
	_, p, state := setupTestServer(t)
	ctx := context.Background()

	// Clear all records.
	state.mu.Lock()
	state.records = nil
	state.mu.Unlock()

	records, err := p.GetRecords(ctx, testZone)
	if err != nil {
		t.Fatalf("GetRecords() error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestGetRecordsZoneNotFound(t *testing.T) {
	_, p, _ := setupTestServer(t)
	ctx := context.Background()

	_, err := p.GetRecords(ctx, "nonexistent.no.")
	if err == nil {
		t.Fatal("expected error for nonexistent zone, got nil")
	}
}

// ---------- AppendRecords tests ----------

func TestAppendRecords(t *testing.T) {
	_, p, state := setupTestServer(t)
	ctx := context.Background()

	// Clear existing records so we can track what's created.
	state.mu.Lock()
	state.records = nil
	state.mu.Unlock()

	newRecs := []libdns.Record{
		libdns.Address{
			Name: "new",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("1.2.3.4"),
		},
		libdns.TXT{
			Name: "_acme-challenge",
			TTL:  120 * time.Second,
			Text: "new-challenge-token",
		},
	}

	created, err := p.AppendRecords(ctx, testZone, newRecs)
	if err != nil {
		t.Fatalf("AppendRecords() error: %v", err)
	}

	if len(created) != 2 {
		t.Fatalf("expected 2 created records, got %d", len(created))
	}

	// Verify the A record was created.
	found := false
	for _, rec := range created {
		rr := rec.RR()
		if rr.Type == "A" && rr.Name == "new" {
			found = true
			break
		}
	}
	if !found {
		t.Error("created A record for 'new' not found in results")
	}

	// Verify the TXT record was created.
	found = false
	for _, rec := range created {
		rr := rec.RR()
		if rr.Type == "TXT" && rr.Name == "_acme-challenge" {
			found = true
			break
		}
	}
	if !found {
		t.Error("created TXT record for '_acme-challenge' not found in results")
	}

	// Verify state has the new records.
	state.mu.Lock()
	if len(state.records) != 2 {
		t.Errorf("expected 2 records in state, got %d", len(state.records))
	}
	state.mu.Unlock()
}

func TestAppendRecordsMX(t *testing.T) {
	_, p, state := setupTestServer(t)
	ctx := context.Background()

	// Clear existing records.
	state.mu.Lock()
	state.records = nil
	state.mu.Unlock()

	newRecs := []libdns.Record{
		libdns.MX{
			Name:       "@",
			TTL:        3600 * time.Second,
			Preference: 20,
			Target:     "mx2.example.no.",
		},
	}

	created, err := p.AppendRecords(ctx, testZone, newRecs)
	if err != nil {
		t.Fatalf("AppendRecords() error: %v", err)
	}

	if len(created) != 1 {
		t.Fatalf("expected 1 created record, got %d", len(created))
	}

	mx, ok := created[0].(libdns.MX)
	if !ok {
		t.Fatalf("expected libdns.MX, got %T", created[0])
	}
	if mx.Preference != 20 {
		t.Errorf("expected MX preference 20, got %d", mx.Preference)
	}
	if mx.Target != "mx2.example.no." {
		t.Errorf("expected MX target %q, got %q", "mx2.example.no.", mx.Target)
	}

	// Verify the record was stored with priority in the mock state.
	state.mu.Lock()
	if len(state.records) != 1 {
		t.Errorf("expected 1 record in state, got %d", len(state.records))
	} else {
		rec := state.records[0]
		if rec.RecordPriority == nil || uint16(*rec.RecordPriority) != 20 {
			t.Errorf("expected record_priority 20 in state, got %v", rec.RecordPriority)
		}
	}
	state.mu.Unlock()
}

// ---------- SetRecords tests ----------

func TestSetRecordsUpdate(t *testing.T) {
	_, p, state := setupTestServer(t)
	ctx := context.Background()

	// Update the existing A record (www → new IP).
	updateRecs := []libdns.Record{
		libdns.Address{
			Name: "www",
			TTL:  7200 * time.Second,
			IP:   netip.MustParseAddr("10.0.0.1"),
		},
	}

	results, err := p.SetRecords(ctx, testZone, updateRecs)
	if err != nil {
		t.Fatalf("SetRecords() error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	rr := results[0].RR()
	if rr.Type != "A" {
		t.Errorf("expected type A, got %s", rr.Type)
	}
	if rr.Name != "www" {
		t.Errorf("expected name 'www', got %q", rr.Name)
	}

	// Verify the state was updated.
	state.mu.Lock()
	var foundRec *ghRecord
	for i := range state.records {
		if state.records[i].RecordID == "101" {
			foundRec = &state.records[i]
			break
		}
	}
	state.mu.Unlock()

	if foundRec == nil {
		t.Fatal("record 101 not found in state after update")
	}
	if foundRec.RecordValue != "10.0.0.1" {
		t.Errorf("expected updated value '10.0.0.1', got %q", foundRec.RecordValue)
	}
	if foundRec.RecordTTL != 7200 {
		t.Errorf("expected updated TTL 7200, got %d", foundRec.RecordTTL)
	}
}

func TestSetRecordsCreate(t *testing.T) {
	_, p, state := setupTestServer(t)
	ctx := context.Background()

	initialCount := len(state.records)

	// Set a record that doesn't exist yet — should create it.
	newRecs := []libdns.Record{
		libdns.TXT{
			Name: "_dmarc",
			TTL:  3600 * time.Second,
			Text: "v=DMARC1; p=none",
		},
	}

	results, err := p.SetRecords(ctx, testZone, newRecs)
	if err != nil {
		t.Fatalf("SetRecords() error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	rr := results[0].RR()
	if rr.Type != "TXT" {
		t.Errorf("expected type TXT, got %s", rr.Type)
	}
	if rr.Name != "_dmarc" {
		t.Errorf("expected name '_dmarc', got %q", rr.Name)
	}

	// Verify a new record was added to state.
	state.mu.Lock()
	if len(state.records) != initialCount+1 {
		t.Errorf("expected %d records in state, got %d", initialCount+1, len(state.records))
	}
	state.mu.Unlock()
}

// ---------- DeleteRecords tests ----------

func TestDeleteRecords(t *testing.T) {
	_, p, state := setupTestServer(t)
	ctx := context.Background()

	initialCount := len(state.records)

	// Delete the A record by providing name and type (which will match record 101).
	deleteRecs := []libdns.Record{
		libdns.Address{
			Name: "www",
			TTL:  3600 * time.Second,
			IP:   netip.MustParseAddr("93.184.216.34"),
		},
	}

	deleted, err := p.DeleteRecords(ctx, testZone, deleteRecs)
	if err != nil {
		t.Fatalf("DeleteRecords() error: %v", err)
	}

	if len(deleted) != 1 {
		t.Fatalf("expected 1 deleted record, got %d", len(deleted))
	}

	rr := deleted[0].RR()
	if rr.Type != "A" {
		t.Errorf("expected deleted type A, got %s", rr.Type)
	}
	if rr.Name != "www" {
		t.Errorf("expected deleted name 'www', got %q", rr.Name)
	}

	// Verify the record was removed from state.
	state.mu.Lock()
	if len(state.records) != initialCount-1 {
		t.Errorf("expected %d records in state, got %d", initialCount-1, len(state.records))
	}
	state.mu.Unlock()
}

func TestDeleteRecordsByNameType(t *testing.T) {
	_, p, state := setupTestServer(t)
	ctx := context.Background()

	initialCount := len(state.records)

	// Delete by name and type only (no value) — uses RR with just name+type.
	deleteRecs := []libdns.Record{
		libdns.RR{
			Name: "_acme-challenge",
			Type: "TXT",
		},
	}

	deleted, err := p.DeleteRecords(ctx, testZone, deleteRecs)
	if err != nil {
		t.Fatalf("DeleteRecords() error: %v", err)
	}

	if len(deleted) != 1 {
		t.Fatalf("expected 1 deleted record, got %d", len(deleted))
	}

	rr := deleted[0].RR()
	if rr.Type != "TXT" {
		t.Errorf("expected deleted type TXT, got %s", rr.Type)
	}

	state.mu.Lock()
	if len(state.records) != initialCount-1 {
		t.Errorf("expected %d records in state, got %d", initialCount-1, len(state.records))
	}
	state.mu.Unlock()
}

func TestDeleteRecordsNotFound(t *testing.T) {
	_, p, state := setupTestServer(t)
	ctx := context.Background()

	initialCount := len(state.records)

	// Try to delete a record that doesn't exist — should silently skip.
	deleteRecs := []libdns.Record{
		libdns.RR{
			Name: "nonexistent",
			Type: "A",
			Data: "1.2.3.4",
		},
	}

	deleted, err := p.DeleteRecords(ctx, testZone, deleteRecs)
	if err != nil {
		t.Fatalf("DeleteRecords() error: %v", err)
	}

	if len(deleted) != 0 {
		t.Errorf("expected 0 deleted records, got %d", len(deleted))
	}

	// Verify no records were removed.
	state.mu.Lock()
	if len(state.records) != initialCount {
		t.Errorf("expected %d records in state, got %d", initialCount, len(state.records))
	}
	state.mu.Unlock()
}

// ---------- Name conversion tests ----------

func TestGhNameToLibdns(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"@", "@"},
		{"www", "www"},
		{"", "@"},
		{"_acme-challenge", "_acme-challenge"},
		{"sub.domain", "sub.domain"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input=%q", tt.input), func(t *testing.T) {
			result := ghNameToLibdns(tt.input)
			if result != tt.expected {
				t.Errorf("ghNameToLibdns(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestLibdnsNameToGh(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"@", "@"},
		{"", "@"},
		{"www", "www"},
		{"_acme-challenge", "_acme-challenge"},
		{"sub.domain", "sub.domain"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input=%q", tt.input), func(t *testing.T) {
			result := libdnsNameToGh(tt.input)
			if result != tt.expected {
				t.Errorf("libdnsNameToGh(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// ---------- Record conversion tests ----------

func TestToLibdnsRecord_A(t *testing.T) {
	rec := ghRecord{
		RecordID:    "1",
		RecordName:  "www",
		RecordType:  "A",
		RecordValue: "93.184.216.34",
		RecordTTL:   3600,
	}

	result, err := toLibdnsRecord(rec, testZone)
	if err != nil {
		t.Fatalf("toLibdnsRecord() error: %v", err)
	}

	addr, ok := result.(libdns.Address)
	if !ok {
		t.Fatalf("expected libdns.Address, got %T", result)
	}
	if addr.Name != "www" {
		t.Errorf("expected name 'www', got %q", addr.Name)
	}
	if addr.IP != netip.MustParseAddr("93.184.216.34") {
		t.Errorf("expected IP 93.184.216.34, got %s", addr.IP)
	}
	if addr.TTL != 3600*time.Second {
		t.Errorf("expected TTL 3600s, got %s", addr.TTL)
	}
}

func TestToLibdnsRecord_AAAA(t *testing.T) {
	rec := ghRecord{
		RecordID:    "2",
		RecordName:  "@",
		RecordType:  "AAAA",
		RecordValue: "2001:db8::1",
		RecordTTL:   3600,
	}

	result, err := toLibdnsRecord(rec, testZone)
	if err != nil {
		t.Fatalf("toLibdnsRecord() error: %v", err)
	}

	addr, ok := result.(libdns.Address)
	if !ok {
		t.Fatalf("expected libdns.Address, got %T", result)
	}
	if addr.IP != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("expected IP 2001:db8::1, got %s", addr.IP)
	}
}

func TestToLibdnsRecord_CNAME(t *testing.T) {
	rec := ghRecord{
		RecordID:    "3",
		RecordName:  "mail",
		RecordType:  "CNAME",
		RecordValue: "mail.example.no",
		RecordTTL:   3600,
	}

	result, err := toLibdnsRecord(rec, testZone)
	if err != nil {
		t.Fatalf("toLibdnsRecord() error: %v", err)
	}

	cname, ok := result.(libdns.CNAME)
	if !ok {
		t.Fatalf("expected libdns.CNAME, got %T", result)
	}
	if cname.Target != "mail.example.no." {
		t.Errorf("expected target 'mail.example.no.', got %q", cname.Target)
	}
}

func TestToLibdnsRecord_MX(t *testing.T) {
	pref := flexUint16(10)
	rec := ghRecord{
		RecordID:       "4",
		RecordName:     "@",
		RecordType:     "MX",
		RecordValue:    "mail.example.no",
		RecordTTL:      3600,
		RecordPriority: &pref,
	}

	result, err := toLibdnsRecord(rec, testZone)
	if err != nil {
		t.Fatalf("toLibdnsRecord() error: %v", err)
	}

	mx, ok := result.(libdns.MX)
	if !ok {
		t.Fatalf("expected libdns.MX, got %T", result)
	}
	if mx.Preference != 10 {
		t.Errorf("expected preference 10, got %d", mx.Preference)
	}
	if mx.Target != "mail.example.no." {
		t.Errorf("expected target 'mail.example.no.', got %q", mx.Target)
	}
}

func TestToLibdnsRecord_TXT(t *testing.T) {
	rec := ghRecord{
		RecordID:    "5",
		RecordName:  "_acme-challenge",
		RecordType:  "TXT",
		RecordValue: "test-challenge-token",
		RecordTTL:   120,
	}

	result, err := toLibdnsRecord(rec, testZone)
	if err != nil {
		t.Fatalf("toLibdnsRecord() error: %v", err)
	}

	txt, ok := result.(libdns.TXT)
	if !ok {
		t.Fatalf("expected libdns.TXT, got %T", result)
	}
	if txt.Text != "test-challenge-token" {
		t.Errorf("expected text 'test-challenge-token', got %q", txt.Text)
	}
	if txt.TTL != 120*time.Second {
		t.Errorf("expected TTL 120s, got %s", txt.TTL)
	}
}

func TestToLibdnsRecord_NS(t *testing.T) {
	rec := ghRecord{
		RecordID:    "6",
		RecordName:  "@",
		RecordType:  "NS",
		RecordValue: "ns1.gigahost.no",
		RecordTTL:   86400,
	}

	result, err := toLibdnsRecord(rec, testZone)
	if err != nil {
		t.Fatalf("toLibdnsRecord() error: %v", err)
	}

	ns, ok := result.(libdns.NS)
	if !ok {
		t.Fatalf("expected libdns.NS, got %T", result)
	}
	if ns.Target != "ns1.gigahost.no." {
		t.Errorf("expected target 'ns1.gigahost.no.', got %q", ns.Target)
	}
}

func TestToGhRecordRequest_A(t *testing.T) {
	rec := libdns.Address{
		Name: "www",
		TTL:  3600 * time.Second,
		IP:   netip.MustParseAddr("93.184.216.34"),
	}

	ghReq := toGhRecordRequest(rec)
	if ghReq.RecordName != "www" {
		t.Errorf("expected name 'www', got %q", ghReq.RecordName)
	}
	if ghReq.RecordType != "A" {
		t.Errorf("expected type 'A', got %q", ghReq.RecordType)
	}
	if ghReq.RecordValue != "93.184.216.34" {
		t.Errorf("expected value '93.184.216.34', got %q", ghReq.RecordValue)
	}
	if ghReq.RecordTTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", ghReq.RecordTTL)
	}
}

func TestToGhRecordRequest_MX(t *testing.T) {
	rec := libdns.MX{
		Name:       "@",
		TTL:        3600 * time.Second,
		Preference: 10,
		Target:     "mail.example.no.",
	}

	ghReq := toGhRecordRequest(rec)
	if ghReq.RecordName != "@" {
		t.Errorf("expected name '@', got %q", ghReq.RecordName)
	}
	if ghReq.RecordType != "MX" {
		t.Errorf("expected type 'MX', got %q", ghReq.RecordType)
	}
	// MX value should be the target without trailing dot.
	if ghReq.RecordValue != "mail.example.no" {
		t.Errorf("expected value 'mail.example.no', got %q", ghReq.RecordValue)
	}
	if ghReq.RecordPriority == nil || *ghReq.RecordPriority != 10 {
		t.Errorf("expected priority 10, got %v", ghReq.RecordPriority)
	}
}

func TestToGhRecordRequest_CNAME(t *testing.T) {
	rec := libdns.CNAME{
		Name:   "mail",
		TTL:    3600 * time.Second,
		Target: "mail.example.no.",
	}

	ghReq := toGhRecordRequest(rec)
	if ghReq.RecordType != "CNAME" {
		t.Errorf("expected type 'CNAME', got %q", ghReq.RecordType)
	}
	// CNAME value should strip trailing dot for Gigahost API.
	if ghReq.RecordValue != "mail.example.no" {
		t.Errorf("expected value 'mail.example.no', got %q", ghReq.RecordValue)
	}
}

func TestToGhRecordRequest_ApexName(t *testing.T) {
	rec := libdns.TXT{
		Name: "@",
		TTL:  120 * time.Second,
		Text: "v=spf1 include:example.no ~all",
	}

	ghReq := toGhRecordRequest(rec)
	if ghReq.RecordName != "@" {
		t.Errorf("expected name '@', got %q", ghReq.RecordName)
	}
}

func TestToGhRecordRequest_EmptyName(t *testing.T) {
	rec := libdns.TXT{
		Name: "",
		TTL:  120 * time.Second,
		Text: "v=spf1",
	}

	ghReq := toGhRecordRequest(rec)
	if ghReq.RecordName != "@" {
		t.Errorf("expected name '@' for empty input, got %q", ghReq.RecordName)
	}
}

// ---------- flexUint16 tests ----------

func TestFlexUint16_UnmarshalNumber(t *testing.T) {
	var f flexUint16
	if err := json.Unmarshal([]byte(`10`), &f); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uint16(f) != 10 {
		t.Errorf("expected 10, got %d", f)
	}
}

func TestFlexUint16_UnmarshalString(t *testing.T) {
	var f flexUint16
	if err := json.Unmarshal([]byte(`"10"`), &f); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uint16(f) != 10 {
		t.Errorf("expected 10, got %d", f)
	}
}

func TestFlexUint16_UnmarshalInRecord(t *testing.T) {
	// Simulate Gigahost API returning record_priority as string.
	data := `{"record_id":"42","record_name":"@","record_type":"MX","record_value":"mail.example.no","record_ttl":3600,"record_priority":"10"}`
	var rec ghRecord
	if err := json.Unmarshal([]byte(data), &rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.RecordPriority == nil {
		t.Fatal("expected non-nil RecordPriority")
	}
	if uint16(*rec.RecordPriority) != 10 {
		t.Errorf("expected 10, got %d", *rec.RecordPriority)
	}
}

func TestFlexUint16_UnmarshalNull(t *testing.T) {
	// Non-MX records have null/missing record_priority.
	data := `{"record_id":"1","record_name":"www","record_type":"A","record_value":"1.2.3.4","record_ttl":3600,"record_priority":null}`
	var rec ghRecord
	if err := json.Unmarshal([]byte(data), &rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.RecordPriority != nil {
		t.Errorf("expected nil RecordPriority, got %v", *rec.RecordPriority)
	}
}

// ---------- Helper function tests ----------

func TestEnsureTrailingDot(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.no", "example.no."},
		{"example.no.", "example.no."},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input=%q", tt.input), func(t *testing.T) {
			result := ensureTrailingDot(tt.input)
			if result != tt.expected {
				t.Errorf("ensureTrailingDot(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRecordMatchesNameType(t *testing.T) {
	ghRec := ghRecord{
		RecordName: "www",
		RecordType: "A",
	}

	// Should match.
	libRec := libdns.Address{Name: "www", IP: netip.MustParseAddr("1.2.3.4")}
	if !recordMatchesNameType(ghRec, libRec) {
		t.Error("expected match for same name+type")
	}

	// Should not match different type.
	libRecTXT := libdns.TXT{Name: "www", Text: "hello"}
	if recordMatchesNameType(ghRec, libRecTXT) {
		t.Error("expected no match for different type")
	}

	// Should not match different name.
	libRecOther := libdns.Address{Name: "other", IP: netip.MustParseAddr("1.2.3.4")}
	if recordMatchesNameType(ghRec, libRecOther) {
		t.Error("expected no match for different name")
	}
}

func TestRecordMatchesNameTypeValue(t *testing.T) {
	ghRec := ghRecord{
		RecordName:  "www",
		RecordType:  "A",
		RecordValue: "93.184.216.34",
	}

	// Should match.
	libRec := libdns.Address{Name: "www", IP: netip.MustParseAddr("93.184.216.34")}
	if !recordMatchesNameTypeValue(ghRec, libRec) {
		t.Error("expected match for same name+type+value")
	}

	// Should not match different value.
	libRecDiff := libdns.Address{Name: "www", IP: netip.MustParseAddr("1.2.3.4")}
	if recordMatchesNameTypeValue(ghRec, libRecDiff) {
		t.Error("expected no match for different value")
	}
}

func TestMatchesForDeletion(t *testing.T) {
	ghRec := ghRecord{
		RecordName:  "www",
		RecordType:  "A",
		RecordValue: "93.184.216.34",
		RecordTTL:   3600,
	}

	// Match by name only (type and value empty = wildcard).
	libRec := libdns.RR{Name: "www"}
	if !matchesForDeletion(ghRec, libRec) {
		t.Error("expected match by name only")
	}

	// Match by name+type.
	libRecTyped := libdns.RR{Name: "www", Type: "A"}
	if !matchesForDeletion(ghRec, libRecTyped) {
		t.Error("expected match by name+type")
	}

	// No match for different name.
	libRecOther := libdns.RR{Name: "other", Type: "A"}
	if matchesForDeletion(ghRec, libRecOther) {
		t.Error("expected no match for different name")
	}

	// No match for different type.
	libRecWrongType := libdns.RR{Name: "www", Type: "AAAA"}
	if matchesForDeletion(ghRec, libRecWrongType) {
		t.Error("expected no match for different type")
	}

	// Match with TTL filter.
	libRecTTL := libdns.RR{Name: "www", Type: "A", TTL: 3600 * time.Second}
	if !matchesForDeletion(ghRec, libRecTTL) {
		t.Error("expected match with matching TTL")
	}

	// No match with wrong TTL.
	libRecWrongTTL := libdns.RR{Name: "www", Type: "A", TTL: 7200 * time.Second}
	if matchesForDeletion(ghRec, libRecWrongTTL) {
		t.Error("expected no match for different TTL")
	}
}
