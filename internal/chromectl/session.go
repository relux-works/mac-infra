package chromectl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

type Session struct {
	OsaScriptPath string
	AXProcessID   func() (int, error)
	AXTypeText    func(int, string, string) error
	AXPress       func(int, string) error
	AXUploadFiles func(int, string, string) error
	uploadPageJS  func(context.Context, string, string, string, string) (browsersession.ExecutionResult, error)
}

type Tab struct {
	WindowID string `json:"windowId"`
	TabID    string `json:"tabId"`
	Title    string `json:"title"`
	URL      string `json:"url"`
	Origin   string `json:"origin,omitempty"`
}

func New() Session {
	return Session{OsaScriptPath: "/usr/bin/osascript"}
}

func (s Session) List(ctx context.Context) ([]Tab, error) {
	out, err := s.runJXA(ctx, listJXA())
	if err != nil {
		return nil, err
	}
	var windows []struct {
		ID   string `json:"id"`
		Tabs []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
			URL   string `json:"url"`
		} `json:"tabs"`
	}
	if err := json.Unmarshal([]byte(out), &windows); err != nil {
		return nil, fmt.Errorf("decode Chrome windows: %w", err)
	}
	var tabs []Tab
	for _, window := range windows {
		for _, tab := range window.Tabs {
			redacted := browsersession.RedactSensitiveURL(tab.URL)
			tabs = append(tabs, Tab{
				WindowID: window.ID,
				TabID:    tab.ID,
				Title:    tab.Title,
				URL:      redacted,
				Origin:   browsersession.OriginOf(redacted),
			})
		}
	}
	return tabs, nil
}

func (s Session) RunJavaScript(ctx context.Context, windowID, tabID, expectedOrigin, source string) (string, error) {
	result, err := s.RunJavaScriptResult(ctx, windowID, tabID, expectedOrigin, source)
	return result.Value, err
}

func (s Session) RunJavaScriptResult(ctx context.Context, windowID, tabID, expectedOrigin, source string) (browsersession.ExecutionResult, error) {
	if strings.TrimSpace(windowID) == "" || strings.TrimSpace(tabID) == "" {
		return browsersession.ExecutionResult{}, errors.New("window id and tab id are required")
	}
	wrapped, err := browsersession.WrapJavaScript(source, expectedOrigin)
	if err != nil {
		return browsersession.ExecutionResult{}, err
	}
	raw, err := s.runAppleScript(ctx, executeAppleScript(), windowID, tabID, wrapped)
	if err != nil {
		return browsersession.ExecutionResult{}, err
	}
	return browsersession.ParseJavaScriptResult(raw, expectedOrigin)
}

func (s Session) Focus(ctx context.Context, windowID, tabID, expectedOrigin string) error {
	_, err := s.focusExactTarget(ctx, windowID, tabID, expectedOrigin)
	return err
}

func (s Session) focusExactTarget(ctx context.Context, windowID, tabID, expectedOrigin string) (exactTargetState, error) {
	if err := validateExactTarget(windowID, tabID, expectedOrigin); err != nil {
		return exactTargetState{}, err
	}
	_, err := s.resolveExactTarget(ctx, windowID, tabID, expectedOrigin, true)
	if err != nil {
		return exactTargetState{}, err
	}
	verified, err := s.resolveExactTarget(ctx, windowID, tabID, expectedOrigin, false)
	if err != nil {
		return exactTargetState{}, err
	}
	if !verified.Active {
		return exactTargetState{}, fmt.Errorf("%w: exact Chrome target is not frontmost and active after focus", browsersession.ErrTargetMissing)
	}
	return verified, nil
}

func (s Session) Close(ctx context.Context, windowID, tabID string) error {
	if strings.TrimSpace(windowID) == "" || strings.TrimSpace(tabID) == "" {
		return errors.New("window id and tab id are required")
	}
	_, err := s.runJXA(ctx, closeJXA(), windowID, tabID)
	return err
}

func FormatAutomationError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "javascript") && (strings.Contains(lower, "apple events") || strings.Contains(lower, "applescript") || strings.Contains(lower, "turned off")) {
		return msg + "\n\nChrome blocked JavaScript automation. Enable View -> Developer -> Allow JavaScript from Apple Events, then rerun the command."
	}
	return msg
}

func listJXA() string {
	return `const c=Application("Google Chrome"); JSON.stringify(c.windows().map(w=>({id:String(w.id()),tabs:w.tabs().map(t=>({id:String(t.id()),title:String(t.title()||""),url:String(t.url()||"")}))})))`
}

func executeAppleScript() string {
	return `on run argv
  set targetWindowID to item 1 of argv as integer
  set targetTabID to item 2 of argv as integer
  set jsSource to item 3 of argv
  tell application "Google Chrome"
    set targetWindows to every window whose id is targetWindowID
    if (count of targetWindows) = 0 then error "Chrome target window is no longer open"
    set targetWindow to item 1 of targetWindows
    set targetTabs to every tab of targetWindow whose id is targetTabID
    if (count of targetTabs) = 0 then error "Chrome target tab is no longer open"
    set targetTab to item 1 of targetTabs
    return execute targetTab javascript jsSource
  end tell
end run`
}

// exactTargetJXA enumerates fresh Chrome arrays instead of dereferencing a
// filtered tab proxy's index property, which fails with -1728 after navigation.
func exactTargetJXA() string {
	return `function run(argv){
  const c=Application("Google Chrome");
  const windowID=String(argv[0]),tabID=String(argv[1]),expectedOrigin=String(argv[2]),selectTab=String(argv[3])==="true";
  const sentinel="works.relux.mac-infra/chrome-exact-target/v1";
  const originOf=(raw)=>{const m=String(raw||"").match(/^(https?):\/\/([^\/?#]+)/i);return m?(m[1].toLowerCase()+"://"+m[2].toLowerCase()):"";};
  const envelope=(outcome,origin,active)=>JSON.stringify({__macChromeExactTarget:sentinel,outcome:outcome,origin:String(origin||""),active:Boolean(active)});
  const windows=c.windows();
  const windowMatches=windows.filter(w=>String(w.id())===windowID);
  if(windowMatches.length!==1)throw new Error("Chrome target window is no longer open");
  const targetWindow=windowMatches[0];
  const tabs=targetWindow.tabs();
  const targetIndexes=[];
  for(let i=0;i<tabs.length;i++)if(String(tabs[i].id())===tabID)targetIndexes.push(i);
  if(targetIndexes.length!==1)throw new Error("Chrome target tab is no longer open");
  const targetIndex=targetIndexes[0];
  const beforeOrigin=originOf(tabs[targetIndex].url());
  if(beforeOrigin!==expectedOrigin)return envelope("origin-mismatch",beforeOrigin,false);
  const freshTabs=targetWindow.tabs();
  if(targetIndex>=freshTabs.length||String(freshTabs[targetIndex].id())!==tabID)throw new Error("Chrome exact target changed before selection");
  if(selectTab){targetWindow.activeTabIndex=targetIndex+1;targetWindow.index=1;c.activate();}
  const verifiedTabs=targetWindow.tabs(),verifiedIndexes=[];
  for(let i=0;i<verifiedTabs.length;i++)if(String(verifiedTabs[i].id())===tabID)verifiedIndexes.push(i);
  if(verifiedIndexes.length!==1)throw new Error("Chrome exact target changed before verification");
  const verifiedIndex=verifiedIndexes[0],verified=verifiedTabs[verifiedIndex];
  const activeIndex=Number(targetWindow.activeTabIndex())-1;
  const frontWindows=c.windows();
  const frontExact=frontWindows.length>0&&String(frontWindows[0].id())===windowID;
  const active=frontExact&&activeIndex===verifiedIndex&&String(verifiedTabs[activeIndex].id())===tabID;
  const afterOrigin=originOf(verified.url());
  if(afterOrigin!==expectedOrigin)return envelope("origin-mismatch",afterOrigin,active);
  return envelope("ok",afterOrigin,active);
}`
}

func closeJXA() string {
	return `function run(argv){const c=Application("Google Chrome");const ws=c.windows.whose({id:Number(argv[0])})();if(!ws.length)throw new Error("Chrome target window is no longer open");const ts=ws[0].tabs.whose({id:Number(argv[1])})();if(!ts.length)return "already-closed";ts[0].close();return "closed";}`
}

func (s Session) runJXA(ctx context.Context, script string, args ...string) (string, error) {
	path := strings.TrimSpace(s.OsaScriptPath)
	if path == "" {
		path = "/usr/bin/osascript"
	}
	cmdArgs := []string{"-l", "JavaScript", "-e", script}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.CommandContext(ctx, path, cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if detail == "" {
			detail = err.Error()
		}
		lower := strings.ToLower(detail)
		if strings.Contains(lower, "target window is no longer open") || strings.Contains(lower, "target tab is no longer open") {
			return "", &browsersession.TargetMissingError{Browser: browsersession.BrowserChrome, Target: strings.Join(args[:min(2, len(args))], "/"), Detail: detail}
		}
		return "", fmt.Errorf("Chrome Apple Events failed: %s", detail)
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}

func (s Session) runAppleScript(ctx context.Context, script string, args ...string) (string, error) {
	path := strings.TrimSpace(s.OsaScriptPath)
	if path == "" {
		path = "/usr/bin/osascript"
	}
	cmdArgs := []string{"-e", script}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.CommandContext(ctx, path, cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if detail == "" {
			detail = err.Error()
		}
		lower := strings.ToLower(detail)
		if strings.Contains(lower, "target window is no longer open") || strings.Contains(lower, "target tab is no longer open") {
			return "", &browsersession.TargetMissingError{Browser: browsersession.BrowserChrome, Target: strings.Join(args[:min(2, len(args))], "/"), Detail: detail}
		}
		return "", fmt.Errorf("Chrome Apple Events failed: %s", detail)
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}
