#!/bin/bash

set -e

mute=">/dev/null 2>&1"
if [[ "$1" == "-v" ]]; then
	mute=
fi

cwd="$(dirname "${BASH_SOURCE[0]}")"
workdir="$(mktemp -d)"
mkdir -p "${workdir}/Logs"
src_dir="$(cd "${cwd}/../" && pwd)"
duplicate_dir="${workdir}/libSession-source"
build_dir="build-ios"
zip_path="${build_dir}/libsession-util.xcframework.zip"
should_clean_up=1

print_usage_and_exit() {
	cat <<- EOF
	Usage:
	  $ $(basename "$0") [-k] [-v] [-h] [<libSession_tag>]

	Options:
	 -h      Show this message
	 -v      Verbose output
	 -k      Keep the temporary directory
	EOF

	rm -rf "$workdir"
	exit 1
}

read_command_line_arguments() {
	while getopts 'hvk' OPTION; do
		case "${OPTION}" in
			h)
				print_usage_and_exit
				;;
			v)
				mute=
				;;
			k)
				should_clean_up=0
				;;
			*)
				;;
		esac
	done

	shift $((OPTIND-1))

	libSession_tag="$1"
	if [[ -z "$libSession_tag" ]]; then
		echo "❌ Please specify the release tag."
		exit 1
	fi

	if [[ "$should_clean_up" == "1" ]]; then
		trap 'rm -rf "$workdir"' EXIT
	fi
}

cleanup() {
  stop_spinner "Process cancelled" "fail"
  exit 1
}

trap cleanup INT TERM

start_spinner() {
  local message="$1"
  local logfile="$2"
  local progress_file="${workdir}/progress.tmp"
  
  # If a logfile is provided, clear any previous progress.
  if [ -n "$logfile" ]; then
  	> "${progress_file}"
  else
  	rm -f "${progress_file}"
  fi

  echo -n "$message "
  
  # Define spinner characters
  spinner='-\|/'

  (
    # Add a trap so that the spinner exits cleanly on SIGTERM or SIGINT
  	trap "exit" SIGTERM SIGINT

    local tail_pid=""
    # If a logfile is specified, tail it to extract percentage progress
    if [ -n "$logfile" ]; then
      tail -n0 -F "$logfile" 2>/dev/null | while read -r line; do
        if [[ "$line" =~ \[[[:space:]]*([0-9]+)% ]]; then
          echo "${BASH_REMATCH[1]}" > "$progress_file"
        fi
      done &
      tail_pid=$!
    fi

    i=0
    # Spinner loop: update the display every 0.2 seconds
    while :; do
      local percent=""
      if [ -n "$logfile" ]; then
        percent=$(cat "$progress_file" 2>/dev/null)
      fi
      # Format the percentage to always occupy 4 characters.
      local disp_percent
      if [ -n "$percent" ]; then
        disp_percent=$(printf "%3d%%" "$percent")
      else
        disp_percent="    "
      fi

      i=$(( (i+1) % ${#spinner} ))
      if [ -n "$logfile" ]; then
        # Display spinner with percentage.
        printf "\r%s %s %s" "$message" "$disp_percent" "${spinner:$i:1}"
      else
        # Display spinner without percentage.
        printf "\r%s %s" "$message" "${spinner:$i:1}"
      fi
      sleep 0.2
    done

    # Cleanup tail process if a logfile was provided.
    if [ -n "$logfile" ]; then
      kill $tail_pid
    fi
  ) &

  # Save the spinner's PID so we can kill it later.
  echo $! > "${workdir}/spinner.pid"
}

stop_spinner() {
  local message="$1"
  local status="$2"  # Expect "success" or "fail"

  kill $(cat "${workdir}/spinner.pid") 2>/dev/null
  rm -f "${workdir}/spinner.pid"

  # Choose an icon based on the status.
  local icon
  if [ "$status" = "success" ]; then
    icon="✅"
  else
    icon="❌"
  fi

  local final_percent="    "
  local progress_file="${workdir}/progress.tmp"
  if [ -f "$progress_file" ]; then
    local last_val
    read -r last_val < "$progress_file"
    if [ -n "$last_val" ]; then
      final_percent=$(printf "%3d%%" "$last_val")
    fi
    rm -f "$progress_file"
  	printf "\r\033[K%s %s %s\n" "$message" "$final_percent" "$icon"
  else
  	echo -e "\r\033[K$message $icon"
  fi
}

duplicate_and_checkout_tag() {
	start_spinner "Copying source to working directory"
	rsync -a --exclude='/build' "${src_dir}/" "${duplicate_dir}"
	stop_spinner "Copying source to working directory" "success"

	start_spinner "Checking out out libSession latest tag: $libSession_tag"
	cd "${duplicate_dir}"
	libSession_tag="${1:-$(git describe --tags --abbrev=0)}"
	eval git checkout -f "${libSession_tag}" "$mute"
	stop_spinner "Checking out out libSession latest tag: $libSession_tag" "success"
}

build_arch() {
	local platform=$1
	local arch=$2
	local log_file=$3

	start_spinner "Building libSession for ${platform} ${arch}" "${workdir}/Logs/${log_file}"
	if TARGET_BUILD_DIR="${build_dir}" PLATFORM_NAME="$platform" ARCHS="$arch" "${duplicate_dir}/utils/ios.sh" "libsession-util" true false false false >"$log_file" 2>&1; then
    	stop_spinner "Building libSession for ${platform} ${arch}" "success"
	else
		stop_spinner "Building libSession for ${platform} ${arch}" "fail"
		mkdir -p "${src_dir}/build/logs" && cp "${workdir}/Logs/${log_file}" "${src_dir}/build/logs/${log_file}"
		echo "Failed to build for ${platform} ${arch}. See log file at ${src_dir}/build/logs/${log_file} for more info."
		exit 1
	fi
}

build_xcframework() {
	cd "${duplicate_dir}"

	# Individually build the different architectures we want to include
	build_arch "iphonesimulator" "arm64" "libsession-util-build-sim-arm64.log"
	build_arch "iphonesimulator" "x86_64" "libsession-util-build-sim-x86_64.log"
	build_arch "iphoneos" "arm64" "libsession-util-build-device-arm64.log"

	# Then merge them into multi-architecture static libraries (as needed)
	local merge_log_file="libsession-util-merge.log"
	start_spinner "Merging libSession architectures"
	if TARGET_BUILD_DIR="${build_dir}" "${duplicate_dir}/utils/ios.sh" "libsession-util" false true false false >"$merge_log_file" 2>&1; then
    	stop_spinner "Merging libSession architectures" "success"
	else
		stop_spinner "Merging libSession architectures" "fail"
		mkdir -p "${src_dir}/build/logs" && cp "${workdir}/Logs/${merge_log_file}" "${src_dir}/build/logs/${merge_log_file}"
		echo "Failed to merge architectures. See log file at ${src_dir}/build/logs/${merge_log_file} for more info."
		exit 1
	fi

	# Create the XCFramework
	local framework_log_file="libsession-util-framework.log"
	start_spinner "Creating libSession XCFramework"
    if TARGET_BUILD_DIR="${build_dir}" "${duplicate_dir}/utils/ios.sh" "libsession-util" false false true false >"$framework_log_file" 2>&1; then
    	stop_spinner "Creating libSession XCFramework" "success"
	else
		stop_spinner "Creating libSession XCFramework" "fail"
		mkdir -p "${src_dir}/build/logs" && cp "${workdir}/Logs/${merge_log_file}" "${src_dir}/build/logs/${framework_log_file}"
		echo "Failed to create XCFramework. See log file at ${src_dir}/build/logs/${framework_log_file} for more info."
		exit 1
	fi

	# And finally archive the XCFramework
	start_spinner "Compressing XCFramework"
	rm -rf "${zip_path}"
	if ditto -c -k --keepParent "${build_dir}/libsession-util.xcframework" "${zip_path}" 2>&1; then
		stop_spinner "Compressing XCFramework" "success"
	else
		stop_spinner "Compressing XCFramework" "fail"
		echo "Failed to compress XCFramework."
		exit 1
	fi
}

update_swift_package() {
	echo -n "Updating Package.swift..."
	export checksum

	checksum=$(swift package compute-checksum "$zip_path")

	cat > "${src_dir}/Package.swift" << EOF
// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LibSessionUtil",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v12)
    ],
    products: [
        .library(name: "SessionUtil", targets: ["SessionUtil"])
    ],
    targets: [
        .binaryTarget(
            name: "SessionUtil",
            url: "https://github.com/oxen-io/libsession-util/releases/download/${libSession_tag}/libsession-util.xcframework.zip",
            checksum: "${checksum}"
        )
    ]
)
EOF

	echo -e "\rUpdating Package.swift ✅"
}

make_release() {
	echo "Making ${libSession_tag} release... 🚢"

	local commit_message="libSession Swift Package Manager ${libSession_tag}"

	git commit -m "$commit_message"

	mv "${zip_path}" "${src_dir}/libsession-util.xcframework.zip"

	echo "🎉 Release is ready to upload, archive at \"./libsession-util.xcframework.zip\""
}

main() {
	read_command_line_arguments "$@"
	
	printf '%s\n' "Using directory at ${workdir}"

	if [[ "$should_clean_up" != "1" ]]; then
		printf '%s\n' "    Note: Directory will not automatically be cleaned up"
	fi

	duplicate_and_checkout_tag "$libSession_tag"
	build_xcframework
	update_swift_package
	make_release
}

main "$@"
