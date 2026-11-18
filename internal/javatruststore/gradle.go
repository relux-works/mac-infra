package javatruststore

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (t Tool) Gradle(ctx context.Context, options Options, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return invalid(CauseGradleWrapper, nil)
	}
	info, err := t.Verify(ctx, options)
	if err != nil {
		return err
	}
	if err := validateGradleArgs(args, info); err != nil {
		return err
	}
	if err := checkGradleProperties(info.ProjectDir, info); err != nil {
		return err
	}
	if err := ensureGradleHome(info.GradleHome); err != nil {
		return err
	}
	if err := checkGradleProperties(info.GradleHome, info); err != nil {
		return err
	}
	wrapper := filepath.Join(info.ProjectDir, "gradlew")
	wrapperInfo, err := os.Lstat(wrapper)
	if err != nil || !wrapperInfo.Mode().IsRegular() || wrapperInfo.Mode().Perm()&0111 == 0 {
		return refusal(CauseGradleWrapper, err)
	}
	arguments := []string{
		"--gradle-user-home=" + info.GradleHome,
		"-Dorg.gradle.java.home=" + info.JavaHome,
		"-Djavax.net.ssl.trustStore=" + info.StorePath,
		"-Djavax.net.ssl.trustStorePassword=" + storePassword,
		"-Djavax.net.ssl.trustStoreType=" + info.StoreType,
	}
	arguments = append(arguments, args...)
	env := gradleEnvironment(os.Environ(), info)
	runner := t.Processes
	if runner == nil {
		runner = ExecRunner{}
	}
	if err := runner.Run(ctx, "./gradlew", arguments, info.ProjectDir, env, stdin, stdout, stderr); err != nil {
		if process, ok := err.(interface{ ExitCode() int }); ok && process.ExitCode() > 0 {
			return &Failure{Code: CauseProcessFailed, Exit: process.ExitCode(), Err: err}
		}
		return operational(CauseProcessFailed, err)
	}
	return nil
}

func validateGradleArgs(args []string, info StoreInfo) error {
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			break
		}
		if value, consumesNext, matched := gradlePathOption(args, index, "--gradle-user-home", "-g"); matched {
			if consumesNext {
				index++
			}
			if !sameScopedDirectory(value, info.GradleHome, info.ProjectDir) {
				return refusal(CauseGradleConfig, nil)
			}
			continue
		}
		if value, consumesNext, matched := gradlePathOption(args, index, "--project-dir", "-p"); matched {
			if consumesNext {
				index++
			}
			if !sameScopedDirectory(value, info.ProjectDir, info.ProjectDir) {
				return refusal(CauseGradleConfig, nil)
			}
			continue
		}
		property, consumesNext := gradleSystemProperty(args, index)
		if consumesNext {
			index++
		}
		if property != "" && systemPropertyConflicts(property, info) {
			return refusal(CauseGradleConfig, nil)
		}
	}
	return nil
}

func gradlePathOption(args []string, index int, long, short string) (string, bool, bool) {
	argument := args[index]
	if argument == long || argument == short {
		if index+1 < len(args) {
			return args[index+1], true, true
		}
		return "", false, true
	}
	if strings.HasPrefix(argument, long+"=") {
		return strings.TrimPrefix(argument, long+"="), false, true
	}
	if strings.HasPrefix(argument, short) && len(argument) > len(short) {
		value := strings.TrimPrefix(argument, short)
		return strings.TrimPrefix(value, "="), false, true
	}
	return "", false, false
}

func sameScopedDirectory(value, expected, base string) bool {
	if value == "" {
		return false
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(base, value)
	}
	absolute, err := filepath.Abs(value)
	return err == nil && filepath.Clean(absolute) == filepath.Clean(expected)
}

func gradleSystemProperty(args []string, index int) (string, bool) {
	argument := args[index]
	switch {
	case argument == "-D" || argument == "--system-prop":
		if index+1 < len(args) {
			return args[index+1], true
		}
	case strings.HasPrefix(argument, "--system-prop="):
		return strings.TrimPrefix(argument, "--system-prop="), false
	case strings.HasPrefix(argument, "-D") && len(argument) > 2:
		return argument[2:], false
	}
	return "", false
}

func systemPropertyConflicts(property string, info StoreInfo) bool {
	key, value, _ := strings.Cut(property, "=")
	if strings.HasPrefix(key, "javax.net.ssl.trustStore") {
		expected := map[string]string{
			"javax.net.ssl.trustStore":         info.StorePath,
			"javax.net.ssl.trustStorePassword": storePassword,
			"javax.net.ssl.trustStoreType":     info.StoreType,
		}
		want, known := expected[key]
		return !known || value != want
	}
	switch key {
	case "gradle.user.home":
		return value != info.GradleHome
	case "org.gradle.java.home":
		return value != info.JavaHome
	case "org.gradle.jvmargs":
		return trustStoreOptionsConflict(value, info)
	}
	return false
}

func gradleEnvironment(base []string, info StoreInfo) []string {
	drop := map[string]bool{
		"JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "JDK_JAVA_OPTIONS": true,
		"JAVA_OPTS": true, "GRADLE_OPTS": true, "JAVA_HOME": true, "GRADLE_USER_HOME": true,
	}
	env := filterEnvironment(base, drop)
	toolOptions := strings.Join([]string{
		"-Djavax.net.ssl.trustStore=" + quoteToolOption(info.StorePath),
		"-Djavax.net.ssl.trustStorePassword=" + storePassword,
		"-Djavax.net.ssl.trustStoreType=" + info.StoreType,
	}, " ")
	return append(env,
		"JAVA_HOME="+info.JavaHome,
		"GRADLE_USER_HOME="+info.GradleHome,
		"JAVA_TOOL_OPTIONS="+toolOptions,
	)
}

func quoteToolOption(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func ensureGradleHome(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0700); err != nil {
			return operational(CauseProcessFailed, err)
		}
		if err := os.Chmod(path, 0700); err != nil {
			return operational(CauseProcessFailed, err)
		}
		return nil
	}
	if err != nil {
		return operational(CauseProcessFailed, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return refusal(CauseSymlink, nil)
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return refusal(CauseStorePermissions, nil)
	}
	return nil
}

func checkGradleProperties(project string, store StoreInfo) error {
	path := filepath.Join(project, "gradle.properties")
	fileInfo, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return operational(CauseGradleConfig, err)
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() {
		return refusal(CauseGradleConfig, nil)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return operational(CauseGradleConfig, err)
	}
	for _, line := range propertyLines(string(data)) {
		key, value, ok := parseProperty(line)
		if !ok {
			continue
		}
		if gradlePropertyConflicts(key, value, store) {
			return refusal(CauseGradleConfig, nil)
		}
	}
	return nil
}

func propertyLines(data string) []string {
	physical := strings.Split(data, "\n")
	logical := make([]string, 0, len(physical))
	var current strings.Builder
	for index, line := range physical {
		if index > 0 && current.Len() > 0 {
			line = strings.TrimLeft(line, " \t\f")
		}
		current.WriteString(line)
		trailing := 0
		for pos := current.Len() - 1; pos >= 0 && current.String()[pos] == '\\'; pos-- {
			trailing++
		}
		if trailing%2 == 1 && index != len(physical)-1 {
			value := current.String()
			current.Reset()
			current.WriteString(value[:len(value)-1])
			continue
		}
		logical = append(logical, current.String())
		current.Reset()
	}
	if current.Len() > 0 {
		logical = append(logical, current.String())
	}
	return logical
}

func parseProperty(line string) (string, string, bool) {
	line = strings.TrimLeft(line, " \t\f")
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return "", "", false
	}
	separator := len(line)
	escaped := false
	for index := 0; index < len(line); index++ {
		character := line[index]
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == '=' || character == ':' || character == ' ' || character == '\t' || character == '\f' {
			separator = index
			break
		}
	}
	key := decodePropertyEscapes(line[:separator])
	value := strings.TrimLeft(line[separator:], " \t\f")
	if strings.HasPrefix(value, "=") || strings.HasPrefix(value, ":") {
		value = value[1:]
	}
	value = strings.TrimLeft(value, " \t\f")
	return key, decodePropertyEscapes(value), true
}

func decodePropertyEscapes(value string) string {
	var decoded strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' || index+1 >= len(value) {
			decoded.WriteByte(value[index])
			continue
		}
		index++
		switch value[index] {
		case 't':
			decoded.WriteByte('\t')
		case 'n':
			decoded.WriteByte('\n')
		case 'r':
			decoded.WriteByte('\r')
		case 'f':
			decoded.WriteByte('\f')
		case 'u':
			if index+4 < len(value) {
				parsed, err := strconv.ParseUint(value[index+1:index+5], 16, 16)
				if err == nil {
					decoded.WriteRune(rune(parsed))
					index += 4
					continue
				}
			}
			decoded.WriteByte('u')
		default:
			decoded.WriteByte(value[index])
		}
	}
	return decoded.String()
}

func gradlePropertyConflicts(key, value string, info StoreInfo) bool {
	if strings.HasPrefix(key, "systemProp.javax.net.ssl.trustStore") {
		return systemPropertyConflicts(strings.TrimPrefix(key, "systemProp.")+"="+value, info)
	}
	switch key {
	case "systemProp.gradle.user.home", "gradle.user.home":
		return value != info.GradleHome
	case "systemProp.org.gradle.java.home", "org.gradle.java.home":
		return value != info.JavaHome
	case "org.gradle.jvmargs":
		return trustStoreOptionsConflict(value, info)
	}
	return false
}

func trustStoreOptionsConflict(value string, info StoreInfo) bool {
	tokens, valid := splitGradleArguments(value)
	if !valid {
		return strings.Contains(value, "javax.net.ssl.trustStore")
	}
	for _, token := range tokens {
		if strings.HasPrefix(token, "-Djavax.net.ssl.trustStore") && systemPropertyConflicts(strings.TrimPrefix(token, "-D"), info) {
			return true
		}
	}
	return false
}

func splitGradleArguments(value string) ([]string, bool) {
	tokens := make([]string, 0)
	var current strings.Builder
	var quote byte
	escaped := false
	started := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if escaped {
			current.WriteByte(character)
			escaped = false
			started = true
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				current.WriteByte(character)
			}
			started = true
			continue
		}
		if character == '"' || character == '\'' {
			quote = character
			started = true
			continue
		}
		if character == ' ' || character == '\t' || character == '\n' || character == '\r' || character == '\f' {
			if started {
				tokens = append(tokens, current.String())
				current.Reset()
				started = false
			}
			continue
		}
		current.WriteByte(character)
		started = true
	}
	if escaped {
		current.WriteByte('\\')
	}
	if quote != 0 {
		return nil, false
	}
	if started {
		tokens = append(tokens, current.String())
	}
	return tokens, true
}
