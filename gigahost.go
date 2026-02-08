package gigahost

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	ghprovider "github.com/fredrik-lindseth/caddy-dns-gigahost/provider"
)

// Provider wraps the Gigahost provider implementation as a Caddy module.
type Provider struct{ *ghprovider.Provider }

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.gigahost",
		New: func() caddy.Module { return &Provider{new(ghprovider.Provider)} },
	}
}

// Provision implements caddy.Provisioner. Resolves placeholders in credentials.
func (p *Provider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	p.Provider.Username = repl.ReplaceAll(p.Provider.Username, "")
	p.Provider.Password = repl.ReplaceAll(p.Provider.Password, "")
	p.Provider.TOTPCode = repl.ReplaceAll(p.Provider.TOTPCode, "")
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	gigahost {
//	    username <username>
//	    password <password>
//	    totp_code <code>
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr() // no inline arguments supported
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "username":
				if p.Provider.Username != "" {
					return d.Err("username already set")
				}
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Provider.Username = d.Val()
			case "password":
				if p.Provider.Password != "" {
					return d.Err("password already set")
				}
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Provider.Password = d.Val()
			case "totp_code":
				if p.Provider.TOTPCode != "" {
					return d.Err("TOTP code already set")
				}
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Provider.TOTPCode = d.Val()
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if p.Provider.Username == "" {
		return d.Err("missing username")
	}
	if p.Provider.Password == "" {
		return d.Err("missing password")
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
)
