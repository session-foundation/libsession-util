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
oxen_rocks_url="https://oxen.rocks/session-foundation/libsession-util"
progress_file="${workdir}/progress.tmp"
should_clean_up=1
should_build_from_source=0

print_usage_and_exit() {
	cat <<- EOF
	Usage:
	  $ $(basename "$0") [-b] [-k] [-v] [-h] [<libSession_tag>]

	Options:
	 -h      Show this message
	 -v      Verbose output
	 -k      Keep the temporary directory
	 -b      Build from source rather than fetching from oxen.rocks
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
			b)
				should_build_from_source=1
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
  echo ""

  # Force kill the spinner and any child processes (like tail)
  if [ -f "${workdir}/spinner.pid" ]; then
    spinner_pid=$(cat "${workdir}/spinner.pid")
    # Get the process group id of the spinner process.
    pgid=$(ps -o pgid= -p "$spinner_pid" | tr -d ' ')
    if [ -n "$pgid" ]; then
      # Kill the entire group (note the negative sign)
      kill -TERM -"$pgid" 2>/dev/null
    else
      # Fallback: kill the spinner process directly
      kill -TERM "$spinner_pid" 2>/dev/null
    fi
  fi

  # Add the 'spinner.stop' as a backup mechanism
  touch "${workdir}/spinner.stop"
  sleep 0.3

  stop_spinner "Process cancelled" "fail"

  exit 1
}

trap cleanup EXIT INT TERM

start_spinner() {
  local message="$1"
  local logfile="$2"
  
  # If a logfile is provided, clear any previous progress.
  if [ -n "$logfile" ]; then
  	> "${progress_file}"
  else
  	rm -f "${progress_file}"
  fi

  echo -n "$message "
  
  # Define spinner characters
  spinner='-\|/'

  # Create a named pipe for communication
  local pipe="${workdir}/spinner.pipe"
  rm -f "$pipe"
  mkfifo "$pipe"

  (
  	trap 'exit 0' SIGTERM SIGINT

    # If a logfile is specified, tail it to extract percentage progress
    if [ -n "$logfile" ]; then
      tail -n0 -F "$logfile" 2>/dev/null | while read -r line; do
      	# Skip empty lines
    	[ -z "$line" ] && continue

      	if [ -f "${workdir}/spinner.stop" ]; then
		  break
		fi

        if [[ "$line" =~ ^[[:space:]]*([0-9]+)\.?[0-9]*% ]]; then
          printf "%s" "${BASH_REMATCH[1]}" > "$progress_file"
		fi
      done &
      local tail_pid=$!

      # Make sure to kill tail when this process exits
      trap "kill $tail_pid 2>/dev/null; exit 0" SIGTERM SIGINT EXIT
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
        printf "\r\033[K%s %s %s" "$message" "$disp_percent" "${spinner:$i:1}"
      else
        # Display spinner without percentage.
        printf "\r\033[K%s %s" "$message" "${spinner:$i:1}"
      fi

      sleep 0.2

      if [ -f "${workdir}/spinner.stop" ]; then
	    break
	  fi
    done

    # Clean up pipe
    rm -f "$pipe"
  ) &

  # Save the spinner's PID so we can kill it later
  spinner_pid=$!
  echo $spinner_pid > "${workdir}/spinner.pid"
}

stop_spinner() {
  local message="$1"
  local status="$2"  # Expect "success", "warn" or "fail"

  if [ -f "${workdir}/spinner.pid" ]; then
  	kill $(cat "${workdir}/spinner.pid") 2>/dev/null || true
  	rm -f "${workdir}/spinner.pid" || true
  fi

  # Choose an icon based on the status.
  local icon
  if [ "$status" = "success" ]; then
    icon="✅"
  elif [ "$status" = "warn" ]; then
  	icon="⚠️"
  else
    icon="❌"
  fi

  local final_percent="    "
  if [ -f "$progress_file" ]; then
    local last_val
    read -r last_val < "$progress_file" 2>/dev/null || true
    if [ -n "$last_val" ]; then
      final_percent=$(printf "%3d%%" "$last_val")
    fi
    rm -f "$progress_file" || true
  	printf "\r\033[K%s %s %s\n" "$message" "$final_percent" "$icon"
  else
  	echo -e "\r\033[K$message $icon"
  fi

  # Always return success
  return 0
}

check_url() {
  local url="$1"
  local output_file="$2"
  local timeout=10
  
  # Use curl with timeout
  if curl -s --connect-timeout $timeout --max-time $timeout -o "$output_file" "$url"; then
    return 0
  else
    return 1
  fi
}

retrieve_ci_build_for_tag() {
	local file_name="libsession-util-ios-${libSession_tag}"
	local file_pattern="${file_name}.tar.xz"
	local download_url=""

	# Create the download dir
	mkdir -p "${workdir}/Downloads"

	# First check in stable directory
	local stable_output="${workdir}/Downloads/stable_output.html"
	start_spinner "Checking for stable ${libSession_tag} build on oxen.rocks"
    
	if check_url "${oxen_rocks_url}/stable/" "${stable_output}"; then
		if grep -q "$file_pattern" "${stable_output}"; then
		    download_url="${oxen_rocks_url}/stable/${file_pattern}"
		    stop_spinner "Checking for stable ${libSession_tag} build on oxen.rocks" "success"
		fi
	fi

	# If we didn't get a download url from the stable branch then fallback to dev
	if [ -z "$download_url" ]; then
	  	stop_spinner "Checking for stable ${libSession_tag} build on oxen.rocks" "warn"

	    # Then check in dev directory
	    local dev_output="${workdir}/Downloads/dev_output.html"
	    start_spinner "Checking for dev ${libSession_tag} build on oxen.rocks"

	    if check_url "${oxen_rocks_url}/dev/" "${dev_output}"; then
	    	if grep -q "$file_pattern" "$dev_output"; then
	        	download_url="${oxen_rocks_url}/dev/${file_pattern}"
	        	stop_spinner "Checking for dev ${libSession_tag} build on oxen.rocks" "success"
	        fi
	    fi
	fi

	# Download the archive
	if [ -z "$download_url" ]; then
		stop_spinner "Checking for dev ${libSession_tag} build on oxen.rocks" "fail"
        echo "Unable to find CI build for ${libSession_tag}."
        exit 1
  	fi

  	# Allow 5 minutes to download the file
	start_spinner "Downloading ${libSession_tag} from $download_url" "${workdir}/Downloads/curl.progress"

	# Get the file size the download the file and track it's progress
	printf "0" > "$progress_file"
	download_file="${workdir}/Downloads/${file_pattern}"
	expected_size=$(curl -sI "$download_url" | awk '/[Cc]ontent-[Ll]ength/ {print $2}' | tr -d '\r')
	curl -f -L --max-time 300 -o "$download_file" "$download_url" > /dev/null 2>&1 &
	curl_pid=$!

	while kill -0 "$curl_pid" 2>/dev/null; do
	    if [ -f "$download_file" ] && [ -n "$expected_size" ]; then
	        # On macOS use: stat -f%z, on Linux use: stat -c%s
	        current_size=$(stat -f%z "$download_file")
	        percent=$(( current_size * 100 / expected_size ))
	        if [ "$percent" -gt 100 ]; then percent=100; fi

	        printf "%s" "$percent" > "$progress_file"
	    fi
	    sleep 0.2
	done

	# Wait for the curl to end
	wait "$curl_pid"
	curl_status=$?

	# Check the curl status
	if [ "$curl_status" -eq 0 ]; then
		printf "100" > "$progress_file"
		stop_spinner "Downloading ${libSession_tag} from $download_url" "success"
	else
		stop_spinner "Downloading ${libSession_tag} from $download_url" "fail"
  		echo "Unable to download ${libSession_tag} from ${download_url}."
  		exit 1
	fi

	# Extract the tar.xz file
	start_spinner "Extracting ${libSession_tag} tar.xz"
    
  	if ! tar -xf "${download_file}" -C "${workdir}/Downloads"; then
  		stop_spinner "Extracting ${libSession_tag} tar.xz" "fail"
  		echo "Failed to extract tar.xz."
        exit 1
    fi

	stop_spinner "Extracting ${libSession_tag} tar.xz" "success"

	# And finally archive the XCFramework
	start_spinner "Compressing XCFramework"
	rm -rf "${zip_path}"
	if ditto -c -k --keepParent "${workdir}/Downloads/${file_name}/libsession-util.xcframework" "${zip_path}" 2>&1; then
		stop_spinner "Compressing XCFramework" "success"
	else
		stop_spinner "Compressing XCFramework" "fail"
		echo "Failed to compress XCFramework."
		exit 1
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
	local build_log_file="${workdir}/Logs/${log_file}"

	start_spinner "Building libSession for ${platform} ${arch}" "${build_log_file}"
	if TARGET_BUILD_DIR="${build_dir}" TARGET_TEMP_DIR="${build_dir}" PLATFORM_NAME="$platform" ARCHS="$arch" "${duplicate_dir}/utils/ios.sh" "libsession-util" true false false false >"${build_log_file}" 2>&1; then
    	stop_spinner "Building libSession for ${platform} ${arch}" "success"
	else
		stop_spinner "Building libSession for ${platform} ${arch}" "fail"
		mkdir -p "${src_dir}/build/logs" && cp "${build_log_file}" "${src_dir}/build/logs/${log_file}"
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

	if [[ "$should_build_from_source" != 1 ]]; then
		retrieve_ci_build_for_tag
	else
		duplicate_and_checkout_tag "$libSession_tag"
		build_xcframework
	fi

	update_swift_package
	make_release
}

main "$@"
