package loadprofile

import "testing"

func TestDefaultCaptureCommandsAreAbsoluteAndReadOnly(t *testing.T) {
	commands := DefaultCaptureCommands(true)
	if len(commands) == 0 {
		t.Fatal("DefaultCaptureCommands returned no commands")
	}

	for _, command := range commands {
		if command.Executable == "" || command.Executable[0] != '/' {
			t.Fatalf("%s executable = %q, want absolute path", command.Name, command.Executable)
		}
		for _, forbidden := range []string{"sh", "bash", "zsh", "sudo", "kill", "killall", "launchctl"} {
			if command.Executable == "/bin/"+forbidden || command.Executable == "/usr/bin/"+forbidden || command.Executable == "/sbin/"+forbidden {
				t.Fatalf("%s uses forbidden executable %q", command.Name, command.Executable)
			}
		}
		if command.Filename == "" {
			t.Fatalf("%s has empty filename", command.Name)
		}
	}
}
