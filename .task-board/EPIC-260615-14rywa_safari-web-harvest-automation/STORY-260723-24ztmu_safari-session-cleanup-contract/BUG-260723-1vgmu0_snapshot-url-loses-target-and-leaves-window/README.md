# BUG-260723-1vgmu0: snapshot-url-loses-target-and-leaves-window

## Description
mac-safari-session snapshot --url can capture the current front Safari page instead of the background page it opened and can leave a zero-tab window object during cleanup

## Scope
Pin snapshot execution to the exact agent-created Safari window/tab and close that exact window after capture without touching user windows

## Acceptance Criteria
snapshot --url returns the requested page even if another Safari window is frontmost; the agent-created window is gone after capture; existing user windows remain untouched
