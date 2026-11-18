// mac-java-truststore builds and uses project-scoped Java truststores.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/mac-infra/internal/javatruststore"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	cancel()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, usage)
		if len(args) == 0 {
			return javatruststore.ExitUsage
		}
		return javatruststore.ExitOK
	}
	action := args[0]
	if action != "build" && action != "verify" && action != "gradle" {
		fmt.Fprintln(stderr, "error: invalid_usage")
		return javatruststore.ExitUsage
	}
	options := javatruststore.Options{}
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.ProjectDir, "project", "", "absolute project directory")
	flags.StringVar(&options.JavaHome, "java-home", "", "absolute JDK home")
	flags.StringVar(&options.Fingerprint, "fingerprint", "", "SHA-256 fingerprint of one System.keychain root")
	flags.StringVar(&options.OutputDir, "out", "", "new output directory relative to the project")
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return javatruststore.ExitOK
		}
		fmt.Fprintf(stderr, "error: %s\n", javatruststore.CauseInvalidUsage)
		return javatruststore.ExitUsage
	}
	if options.ProjectDir == "" || options.JavaHome == "" || options.Fingerprint == "" || options.OutputDir == "" {
		fmt.Fprintf(stderr, "error: %s\n", javatruststore.CauseInvalidUsage)
		return javatruststore.ExitUsage
	}
	if action != "gradle" && flags.NArg() != 0 {
		fmt.Fprintf(stderr, "error: %s\n", javatruststore.CauseInvalidUsage)
		return javatruststore.ExitUsage
	}
	tool := javatruststore.Tool{}
	switch action {
	case "build":
		_, err := tool.Build(ctx, options)
		if err != nil {
			return reportError(stderr, err)
		}
		fmt.Fprintln(stdout, "truststore created")
		return javatruststore.ExitOK
	case "verify":
		_, err := tool.Verify(ctx, options)
		if err != nil {
			return reportError(stderr, err)
		}
		fmt.Fprintln(stdout, "truststore verified")
		return javatruststore.ExitOK
	case "gradle":
		if flags.NArg() == 0 {
			fmt.Fprintf(stderr, "error: %s\n", javatruststore.CauseInvalidUsage)
			return javatruststore.ExitUsage
		}
		if err := tool.Gradle(ctx, options, flags.Args(), os.Stdin, stdout, stderr); err != nil {
			return reportError(stderr, err)
		}
		return javatruststore.ExitOK
	default:
		return javatruststore.ExitUsage
	}
}

func reportError(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "error: %s\n", javatruststore.Cause(err))
	return javatruststore.ExitCode(err)
}

const usage = `mac-java-truststore build --project DIR --java-home DIR --fingerprint SHA256 --out RELATIVE_DIR
mac-java-truststore verify --project DIR --java-home DIR --fingerprint SHA256 --out RELATIVE_DIR
mac-java-truststore gradle --project DIR --java-home DIR --fingerprint SHA256 --out RELATIVE_DIR -- GRADLE_ARGS...

build: copy JDK cacerts and add the one matching public System.keychain CA root.
verify: check the store and source hashes without rebuilding.
gradle: verify, then run only the project ./gradlew with project-local JVM settings.
Exit: 0 success, 2 usage, 3 refused, 4 operational failure; gradle propagates its exit status.`
