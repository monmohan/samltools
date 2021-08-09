package samltools

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	mrand "math/rand"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestXMLGen(t *testing.T) {
	req := &AuthnRequest{
		SamlpAttr:       "urn:oasis:names:tc:SAML:2.0:protocol",
		ID:              "123",
		IssueInstant:    time.Now().Format(time.RFC3339),
		ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Version:         "2.0",
		Issuer:          Issuer{Namespace: "urn:oasis:names:tc:SAML:2.0:assertion", Value: "http://msinghlocal.saml.com"},
	}
	output, err := xml.MarshalIndent(req, "  ", "    ")
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}

	os.Stdout.Write(output)
}

//idp cert

var resp = `PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJfOGNiMWM4OWY4NGRiOTZkYmFkYWQiICBJblJlc3BvbnNlVG89Il81NTk3ODE3NDgzMjAyMjUyMzI3IiAgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMjEtMDctMjVUMTA6MTY6MTAuNTMxWiIgIERlc3RpbmF0aW9uPSJodHRwOi8vc3Auc2FtbHRvb2xzLmNvbTo0NTY3L2Fzc2VydGlvbiI+PHNhbWw6SXNzdWVyIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPnVybjpkZXYtZWp0bDk4OHcuYXV0aDAuY29tPC9zYW1sOklzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48c2FtbDpBc3NlcnRpb24geG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgVmVyc2lvbj0iMi4wIiBJRD0iX2RPS3BPUWh6bnpIa291TFFqV1dVUEtZQm1EaHBGMHN0IiBJc3N1ZUluc3RhbnQ9IjIwMjEtMDctMjVUMTA6MTY6MTAuNTA0WiI+PHNhbWw6SXNzdWVyPnVybjpkZXYtZWp0bDk4OHcuYXV0aDAuY29tPC9zYW1sOklzc3Vlcj48U2lnbmF0dXJlIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48U2lnbmVkSW5mbz48Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz48UmVmZXJlbmNlIFVSST0iI19kT0twT1Foem56SGtvdUxRaldXVVBLWUJtRGhwRjBzdCI+PFRyYW5zZm9ybXM+PFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvVHJhbnNmb3Jtcz48RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48RGlnZXN0VmFsdWU+c2ZKTFBhdnlLSExoVVJvWjlVb2FwbVRXbFZVPTwvRGlnZXN0VmFsdWU+PC9SZWZlcmVuY2U+PC9TaWduZWRJbmZvPjxTaWduYXR1cmVWYWx1ZT5OcncxcjlCekRJbEQ5ai9SM2dsYVJsem9Db0liczBucFYySEMvRUMwWkEvRXV4WnFma1NnVUVZdiswTVI4aDBsV3VhWDdTKzB6OElVYi9mU0pvY3JrSldHWFpQR0xYbnpudkVrcExOSmNBNmxOUG8vcEhXUm94NzhqK0RSMGdFR014YnZBanZoMFYvQ2NXa2d2SzhhSUV3bGU2QUdFY2RvWDM2N2ViaXNLQ3hjVlcvbDg1cFYvNGNnb0o4MmFzK1ozMlEzRnJtL1V2WUpBUVVwbVhVSUpzeFV5cFJucTBjeWFjdHBXeGNDZVdHVlJ6QUczR2JoUkpWMENiWmN6ZmI0UlhwQjYwR25MNWp4WEx5V1BORzRTeGtWS2dUOExFZVJQSXFUY2Z6OXE0b1VhaW1MUVRzTWFPakdVZER2b21NbkllOENWbFFXeVdNVnBMSmw3dGc4OHc9PTwvU2lnbmF0dXJlVmFsdWU+PEtleUluZm8+PFg1MDlEYXRhPjxYNTA5Q2VydGlmaWNhdGU+TUlJREJ6Q0NBZStnQXdJQkFnSUpha29QaG8wTUpyNTZNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1DRXhIekFkQmdOVkJBTVRGbVJsZGkxbGFuUnNPVGc0ZHk1aGRYUm9NQzVqYjIwd0hoY05NVGt4TURJNU1qSXdOekl5V2hjTk16TXdOekEzTWpJd056SXlXakFoTVI4d0hRWURWUVFERXhaa1pYWXRaV3AwYkRrNE9IY3VZWFYwYURBdVkyOXRNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXprTTFRSGNQMHY4Ym13UTJmZDNQajZ1bkNUeDVrOExzVzljdUx0VWhBamp6UkdwU0V3R0NLRWdpMWVqMiswQ3hjczF0MHd6aE8relN2MVRKYnNESTB4ODYyUElGRXMzeGtHcVBaVTZyZlFNenZDbW5jQWNNanVXN3IvWmV3bTBzNThvUkd5aWMxT3lwOHhpeTc4Y3psQkcwM2prLysvdmR0dEpraWU4cFVjOUFIQnVNeEFhVjRpUE4zelNpL0o1T1ZTbG92azYwN0gzQVVpTDNCZmc0c3NTMWJzSnZhRkcwa3VOc2NvaVArcUxSVGpGSzZMelpTOTlWeGVnZU56dHRxR2J0ajVCd05nYnR1enJJeWZMbVlCLzlWZ0V3K1FkYVFIdnhvQXZEMGY3YVlzYUoxUjZycnF4bysxUHVuN2oxL2g3a09DR0IwVWNIRExEdzdnYVAvd0lEQVFBQm8wSXdRREFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQjBHQTFVZERnUVdCQlF3SW9vNlF6elVML1RjTlZwTEdyTGRkM0RBSXpBT0JnTlZIUThCQWY4RUJBTUNBb1F3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUxiOFF5Y1JtYXV5Qy9IUldSeFRibDB3MjMxSFRBVllpelFxaEZRRmwzYmVTUUloZXhHaWsrSCtCNHZlMnJ2OTRRUkQzTGxyYVVwK0oyNndMRzg5RW5TQ3VDby9PeFBBcStseE82aE5mNm9LSitZMmY0OGF3SU94b2xPMGY4OXFYM0tNSWtBQlh3S2JZVWNkK1NCSFg1WlAxVjljdkpFeUgwczNGcTlPYnlzUENIMmoySGpnejNXTUlmZlNGTWFPMERJZmgzZU5udjloS1F3YXZVTzdmTC9qcWhCbDRReEkyZ015U2kwTmk3UGdBbEJneEJ4NllVcDU5cS9sek1nQWYxOUdPRU92STdsNGRBMGJjOXBkc203T2hpbXNrdk9VU1pZaTVQejNuL2kvY1RWS0tobGo2TnlJTmtNWGxYR2d5TTl2RUJwZGNJcE9Xbi8xSDVRVnk4UT08L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48L1NpZ25hdHVyZT48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OnVuc3BlY2lmaWVkIj5hdXRoMHw1ZmZhZmI0OGQ5ZmY5YjAwNzBjNTJlYWI8L3NhbWw6TmFtZUlEPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMjEtMDctMjVUMTE6MTY6MTAuNTA0WiIgUmVjaXBpZW50PSJodHRwOi8vc3Auc2FtbHRvb2xzLmNvbTo0NTY3L2Fzc2VydGlvbiIgSW5SZXNwb25zZVRvPSJfNTU5NzgxNzQ4MzIwMjI1MjMyNyIvPjwvc2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uPjwvc2FtbDpTdWJqZWN0PjxzYW1sOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDIxLTA3LTI1VDEwOjE2OjEwLjUwNFoiIE5vdE9uT3JBZnRlcj0iMjAyMS0wNy0yNVQxMToxNjoxMC41MDRaIj48c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjxzYW1sOkF1ZGllbmNlPmh0dHA6Ly9zcC5zYW1sdG9vbHMuY29tPC9zYW1sOkF1ZGllbmNlPjwvc2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjwvc2FtbDpDb25kaXRpb25zPjxzYW1sOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAyMS0wNy0yNVQxMDoxNjoxMC41MDRaIiBTZXNzaW9uSW5kZXg9Il9oREt2cnhfN3JHUDRGbE9LbU5hSlJuSEdNQXlHdUpuNyI+PHNhbWw6QXV0aG5Db250ZXh0PjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOnVuc3BlY2lmaWVkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDpBdXRobkNvbnRleHQ+PC9zYW1sOkF1dGhuU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZVN0YXRlbWVudCB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJuYW1lIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5hdXRoMHw1ZmZhZmI0OGQ5ZmY5YjAwNzBjNTJlYWI8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iZW1haWwiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmRldi5udWxsLmR1bXAuMUBnbWFpbC5jb208L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvdXBuIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+ZGV2Lm51bGwuZHVtcC4xQGdtYWlsLmNvbTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5hdXRoMC5jb20vaWRlbnRpdGllcy9kZWZhdWx0L3Byb3ZpZGVyIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+YXV0aDA8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL2lkZW50aXRpZXMvZGVmYXVsdC9jb25uZWN0aW9uIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+VXNlcm5hbWUtUGFzc3dvcmQtQXV0aGVudGljYXRpb248L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL2lkZW50aXRpZXMvZGVmYXVsdC9pc1NvY2lhbCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpib29sZWFuIj5mYWxzZTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5hdXRoMC5jb20vY2xpZW50SUQiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5scXJiV1dNWWMyNVVyQ2lZQTVQdDA2VTYyNWM0SzZETzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5hdXRoMC5jb20vY3JlYXRlZF9hdCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czphbnlUeXBlIj5TdW4gSmFuIDEwIDIwMjEgMTM6MDQ6MDggR01UKzAwMDAgKENvb3JkaW5hdGVkIFVuaXZlcnNhbCBUaW1lKTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5hdXRoMC5jb20vZW1haWxfdmVyaWZpZWQiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6Ym9vbGVhbiI+ZmFsc2U8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL25hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5kZXYubnVsbC5kdW1wLjFAZ21haWwuY29tPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS9uaWNrbmFtZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmRldi5udWxsLmR1bXAuMTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5hdXRoMC5jb20vcGljdHVyZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmh0dHBzOi8vcy5ncmF2YXRhci5jb20vYXZhdGFyLzQzNTU3YzU4ZGY4NGE1NDY3NGUwNGQ1NTg5OWIyNTE3P3M9NDgwJmFtcDtyPXBnJmFtcDtkPWh0dHBzJTNBJTJGJTJGY2RuLmF1dGgwLmNvbSUyRmF2YXRhcnMlMkZkZS5wbmc8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL3VwZGF0ZWRfYXQiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6YW55VHlwZSI+U2F0IEp1bCAyNCAyMDIxIDAzOjQ2OjA0IEdNVCswMDAwIChDb29yZGluYXRlZCBVbml2ZXJzYWwgVGltZSk8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL2xhc3RfcGFzc3dvcmRfcmVzZXQiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4yMDIxLTAxLTEyVDA2OjA2OjI3LjY4N1o8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48L3NhbWw6QXR0cmlidXRlU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4=`

func TestValidateSignature(t *testing.T) {
	err := ValidateAssertion(resp, nil)
	if err != nil {
		t.Fatalf("Validation Failed Err=%s", err)

	}
}

func TestCreateAssertion(t *testing.T) {
	mrand.Seed(time.Now().UnixNano())

	//create assertion
	assertionID := fmt.Sprintf("_%d", mrand.Int())
	issueTime := time.Now().Format(time.RFC3339)
	notOnOrAfter := time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	requestId := fmt.Sprintf("_%d", mrand.Int())
	doc := etree.NewDocument()
	asEl := doc.CreateElement("saml:Assertion")
	asEl.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	asEl.CreateAttr("Version", "2.0")
	asEl.CreateAttr("ID", assertionID)
	asEl.CreateAttr("IssueInstant", issueTime)
	//add Issuer
	asEl.CreateElement("saml:Issuer").CreateText("http://idp.samltools.com")

	addSubject(asEl, requestId, notOnOrAfter)
	addConditions(asEl, notOnOrAfter)
	addAuthStatements(asEl, issueTime)

	attrStmts := asEl.CreateElement("saml:AttributeStatement")
	attrStmts.CreateAttr("xmlns", "http://www.w3.org/2001/XMLSchema")
	attrStmts.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	createAttribute(attrStmts, "name", "IDPUser1")
	createAttribute(attrStmts, "email", "dev.null.dump.1@gmail.com")
	createAttribute(attrStmts, "userid", "IDPUser1")

	samlResp := createSAMLResponseElement(asEl, requestId)

	//randomKeyStore := dsig.RandomKeyStoreForTest()
	randomKeyStore := NewIDPKeyStore()
	ctx := dsig.NewDefaultSigningContext(randomKeyStore)
	// Sign the element
	signedElement, err := ctx.SignEnveloped(asEl)
	if err != nil {
		panic(err)
	}
	samlResp.AddChild(signedElement)
	// Serialize the signed element. It is important not to modify the element
	// after it has been signed - even pretty-printing the XML will invalidate
	// the signature.
	fdoc := etree.NewDocument()
	fdoc.SetRoot(samlResp)
	fdoc.WriteTo(os.Stdout)

	bytes, err := fdoc.WriteToBytes()
	if err != nil {
		panic(err)
	}
	resp := base64.StdEncoding.EncodeToString(bytes)
	//Build context
	_, certBytes, _ := randomKeyStore.GetKeyPair()
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		panic(err)
	}

	certificateStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}

	validationContext := dsig.NewDefaultValidationContext(&certificateStore)
	validationContext.IdAttribute = "ID"

	err = ValidateAssertion(resp, validationContext)
	if err != nil {
		t.Fatalf("failed to validate signature  %s", err.Error())
	}

}

func addSignature(asEl *etree.Element, signedInfo *etree.Element, sigValue string) {
	signEl := asEl.CreateElement("Signature")
	signEl.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
	signEl.AddChild(signedInfo)
	signEl.CreateElement("SignatureValue").CreateText(sigValue)
	X509Cert := signEl.CreateElement("KeyInfo").CreateElement("X509Data").CreateElement("X509Certificate")
	X509Cert.CreateText(Certb64)
}

func createSignedInfo(digestValue string, assertionID string) *etree.Element {
	doc := etree.NewDocument()
	siEl := doc.CreateElement("SignedInfo")
	cmEl := siEl.CreateElement("CanonicalizationMethod")
	cmEl.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	smEl := siEl.CreateElement("SignatureMethod")
	smEl.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
	refEl := siEl.CreateElement("Reference")
	refEl.CreateAttr("URI", fmt.Sprintf("#%s", assertionID))
	trfsEl := refEl.CreateElement("Transforms")
	trfEl1 := trfsEl.CreateElement("Transform")
	trfEl1.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
	trfEl2 := trfsEl.CreateElement("Transform")
	trfEl2.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	dmEl := refEl.CreateElement("DigestMethod")
	dmEl.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
	dvEl := refEl.CreateElement("DigestValue")
	dvEl.CreateText(digestValue)
	return siEl
}

func canonicalSerialize(el *etree.Element) ([]byte, error) {
	canonicalizer := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	return canonicalizer.Canonicalize(el)
	/*doc := etree.NewDocument()
	doc.SetRoot(transformed.Copy())

	doc.WriteSettings = etree.WriteSettings{
		CanonicalAttrVal: true,
		CanonicalEndTags: true,
		CanonicalText:    true,
	}*/

	//return transformed
}

func digest(el *etree.Element, digestAlgorithmId string, canonicalizer dsig.Canonicalizer) ([]byte, error) {
	data, err := canonicalizer.Canonicalize(el)
	if err != nil {
		return nil, err
	}

	digestAlgorithm := crypto.SHA1

	hash := digestAlgorithm.New()
	_, err = hash.Write(data)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func signWithPvtkey(hashed []byte) ([]byte, error) {
	pemBlock, _ := ioutil.ReadFile("config/idp-samltools-privatekey.key")
	block, _ := pem.Decode(pemBlock)
	if block == nil {
		panic("failed to parse PEM block containing the private key")
	}

	pvt, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}
	key := pvt.(*rsa.PrivateKey)

	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, hashed)

}

func TestSignature(t *testing.T) {
	message := "this is some message"
	hash := crypto.SHA1.New()
	_, err := hash.Write([]byte(message))
	if err != nil {
		log.Fatalf("failed to create hash  %s", err.Error())
	}

	hashed := hash.Sum(nil)
	signature, err := signWithPvtkey(hashed)
	if err != nil {
		log.Fatalf("failed to create signature  %s", err.Error())
	}
	derBytesCert, err := base64.StdEncoding.DecodeString(Certb64)

	cert, err := x509.ParseCertificate(derBytesCert)
	if err != nil {
		log.Fatalf("x509 parse err %s\n", err.Error())

	}
	err = rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA1, hashed, signature)
	if err != nil {
		log.Fatalf("check failed signature err %s\n", err.Error())

	}
}
