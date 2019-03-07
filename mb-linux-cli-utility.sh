#!/usr/bin/env bash
#
# Script to setup/configure MediaButler.
# Tronyx
set -eo pipefail
IFS=$'\n\t'

# Define variables
mbLoginURL='https://auth.mediabutler.io/login'
mbDiscoverURL='https://auth.mediabutler.io/login/discover'
mbClientID='MB-Client-Identifier: 4d656446-fbe7-4545-b754-1adfb8eb554e'
mbClientIDShort='4d656446-fbe7-4545-b754-1adfb8eb554e'
# Set initial Plex credentials status
plexCredsStatus='ok'
# Set initial Tautulli credentials status
tautulliURLStatus='invalid'
tautulliAPIKeyStatus='invalid'
# Set initial Sonarr credentials status
sonarrURLStatus='invalid'
sonarrAPIKeyStatus='invalid'
# Set initial Sonarr 4K credentials status
sonarr4kURLStatus='invalid'
sonarr4kAPIKeyStatus='invalid'
# Set initial Radarr credentials status
radarrURLStatus='ok'
radarrAPIKeyStatus='ok'
# Set initial Radarr 4K credentials status
radarr4kURLStatus='invalid'
radarr4kAPIKeyStatus='invalid'
# Set initial Radarr 3D credentials status
radarr3dURLStatus='invalid'
radarr3dAPIKeyStatus='invalid'

# Define temp dir and files
tempDir='/tmp/mb_setup/'
plexCredsFile="${tempDir}plex_creds_check.txt"
plexTokenFile="${tempDir}plex_token.txt"
plexServerMachineIDFile="${tempDir}plex_machineID.txt"
userMBURLFile="${tempDir}user_mb_url.txt"
plexServerMBTokenFile="${tempDir}plex_server_mb_token.txt"
plexServersFile="${tempDir}plex_server_list.txt"
numberedPlexServersFile="${tempDir}numbered_plex_server_list.txt"
tautulliConfigFile="${tempDir}tautulli_config.txt"
rawArrProfilesFile="${tempDir}raw_arr_profiles.txt"
arrProfilesFile="${tempDir}arr_profiles.txt"
numberedArrProfilesFile="${tempDir}numbered_arr_profiles.txt"
rawArrRootDirsFile="${tempDir}raw_arr_root_dirs.txt"
arrRootDirsFile="${tempDir}arr_root_dirs.txt"
numberedArrRootDirsFile="${tempDir}numbered_arr_root_dirs.txt"
sonarrConfigFile="${tempDir}sonarr_config.txt"
sonarr4kConfigFile="${tempDir}sonarr4k_config.txt"
radarrConfigFile="${tempDir}radarr_config.txt"
radarr4KConfigFile="${tempDir}radarr4k_config.txt"
radarr3DConfigFile="${tempDir}radarr3d_config.txt"

# Define text colors
readonly blu='\e[34m'
readonly lblu='\e[94m'
readonly grn='\e[32m'
readonly red='\e[31m'
readonly ylw='\e[33m'
readonly org='\e[38;5;202m'
readonly lorg='\e[38;5;130m'
readonly mgt='\e[35m'
readonly endColor='\e[0m'

# Script Information
get_scriptname() {
  local source
  local dir
  source="${BASH_SOURCE[0]}"
  while [[ -L ${source} ]]; do
    dir="$(cd -P "$(dirname "${source}")" > /dev/null && pwd)"
    source="$(readlink "${source}")"
    [[ ${source} != /* ]] && source="${dir}/${source}"
  done
  echo "${source}"
}

readonly scriptname="$(get_scriptname)"
readonly scriptpath="$(cd -P "$(dirname "${scriptname}")" > /dev/null && pwd)"

# Check whether or not user is root or used sudo
root_check() {
  if [[ ${EUID} -ne 0 ]]; then
    echo -e "${red}You didn't run the script as root!${endColor}"
    echo -e "${ylw}Doing it for you now...${endColor}"
    echo ''
    sudo bash "${scriptname:-}" "${args[@]:-}"
    exit
  fi
}

# Function to check Bash is >=4 and, if not, exit w/ message
check_bash() {
  bashMajorVersion=$(bash --version |grep -v grep |grep release |awk '{print $4}' |cut -c1)
  if [ "${bashMajorVersion}" -lt '4' ]; then
    echo -e "${red}This script requires Bash v4 or higher!${endColor}"
    echo -e "${ylw}Please upgrade Bash on this system and then try again.${endColor}"
  elif [ "${bashMajorVersion}" -ge '4' ]; then
    :
  fi
}

# Function to check Sed is >= and, if not,  exit w/ message
check_sed() {
  if [ "${packageManager}" = 'mac' ]; then
    sedMajorVersion=$(gsed --version |head -1 |awk '{print $4}' |cut -c1)
  else
    sedMajorVersion=$(sed --version |head -1 |awk '{print $4}' |cut -c1)
  fi
  if [ "${sedMajorVersion}" -lt '4' ]; then
    echo -e "${red}This script requires Sed v4 or higher!${endColor}"
    echo -e "${ylw}Please upgrade Sed on this system and then try again.${endColor}"
    if [ "${packageManager}" = 'mac' ]; then
      echo -e "${ylw}If you are on a Mac you will need to install/upgrade gnu-sed.${endColor}"
    else
      :
    fi
  elif [ "${sedMajorVersion}" -ge '4' ]; then
    :
  fi
}

# Function to determine which Package Manager to use
package_manager() {
  declare -A osInfo;
  osInfo[/etc/redhat-release]='yum -y -q'
  osInfo[/etc/arch-release]=pacman
  osInfo[/etc/gentoo-release]=emerge
  osInfo[/etc/SuSE-release]=zypp
  osInfo[/etc/debian_version]='apt-get -y -qq'
  osInfo[/etc/alpine-release]='apk'
  osInfo[/System/Library/CoreServices/SystemVersion.plist]='mac'

  for f in "${!osInfo[@]}"
    do
      if [[ -f $f ]];then
        packageManager=${osInfo[$f]}
      fi
    done
}

# Function to check if cURL is installed and, if not, install it
check_curl() {
  whichCURL=$(which curl)
  if [ -z "${whichCURL}" ]; then
    echo -e "${red}cURL is not currently installed!${endColor}"
    echo -e "${ylw}Doing it for you now...${endColor}"
    if [ "${packageManager}" = 'apk' ]; then
      apk add --no-cache curl
    elif [ "${packageManager}" = 'mac' ]; then
      /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)" && /usr/local/bin/brew install jq
    else
      "${packageManager}" install curl
    fi
  else
    :
  fi
  whichCURL=$(which curl)
  if [ -z "${whichCURL}" ]; then
    echo -e "${red}We tried, and failed, to install cURL!${endColor}"
    exit 1
  else
    :
  fi
}

# Function to check if JQ is installed and, if not, install it
check_jq() {
  whichJQ=$(which jq)
  if [ -z "${whichJQ}" ]; then
    echo -e "${red}JQ is not currently installed!${endColor}"
    echo -e "${ylw}Doing it for you now...${endColor}"
    if [ "${packageManager}" = 'apk' ]; then
      apk add --no-cache jq
    elif [ "${packageManager}" = 'mac' ]; then
      /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)" && /usr/local/bin/brew install jq
    else
      "${packageManager}" install jq
    fi
  else
    :
  fi
  whichJQ=$(which jq)
  if [ -z "${whichJQ}" ]; then
    echo -e "${red}We tried, and failed, to install JQ!${endColor}"
    exit 1
  else
    :
  fi
}

# Function to bundle checks
checks() {
  root_check
  check_bash
  package_manager
  check_curl
  check_jq
  check_sed
}

# Create directory to neatly store temp files
create_dir() {
  mkdir -p "${tempDir}"
  chmod 777 "${tempDir}"
}

# Cleanup temp files
cleanup() {
  rm -rf "${tempDir}"*.txt || true
  rm -rf "${scriptname}".bak || true
}

# Exit the script if the user hits CTRL+C
function control_c() {
  exit
}
trap 'control_c' 2

# Grab status variable line numbers
get_line_numbers() {
  plexCredsStatusLineNum=$(head -50 "${scriptname}" |grep -En -A1 'Set initial Plex credentials status' |tail -1 | awk -F- '{print $1}')
  tautulliURLStatusLineNum=$(head -50 "${scriptname}" |grep -En -A2 'Set initial Tautulli credentials status' |grep URL |awk -F- '{print $1}')
  tautulliAPIKeyStatusLineNum=$(head -50 "${scriptname}" |grep -En -A2 'Set initial Tautulli credentials status' |grep API |awk -F- '{print $1}')
  sonarrURLStatusLineNum=$(head -50 "${scriptname}" |grep -En -A2 'Set initial Sonarr credentials status' |grep URL |awk -F- '{print $1}')
  sonarrAPIKeyStatusLineNum=$(head -50 "${scriptname}" |grep -En -A2 'Set initial Sonarr credentials status' |grep API |awk -F- '{print $1}')
  sonarr4kURLStatusLineNum=$(head -50 "${scriptname}" |grep -En -A2 'Set initial Sonarr 4K credentials status' |grep URL |awk -F- '{print $1}')
  sonarr4kAPIKeyStatusLineNum=$(head -50 "${scriptname}" |grep -En -A2 'Set initial Sonarr 4K credentials status' |grep API |awk -F- '{print $1}')
  radarrURLStatusLineNum=$(head -50 "${scriptname}" |grep -En -A2 'Set initial Radarr credentials status' |grep URL |awk -F- '{print $1}')
  radarrAPIKeyStatusLineNum=$(head -50 "${scriptname}" |grep -En -A2 'Set initial Radarr credentials status' |grep API |awk -F- '{print $1}')
  radarr4kURLStatusLineNum=$(head -50 "${scriptname}" |grep -En -A2 'Set initial Radarr 4K credentials status' |grep URL |awk -F- '{print $1}')
  radarr4kAPIKeyStatusLineNum=$(head -50 "${scriptname}" |grep -En -A2 'Set initial Radarr 4K credentials status' |grep API |awk -F- '{print $1}')
  radarr3dURLStatusLineNum=$(head -50 "${scriptname}" |grep -En -A2 'Set initial Radarr 3D credentials status' |grep URL |awk -F- '{print $1}')
  radarr3dAPIKeyStatusLineNum=$(head -50 "${scriptname}" |grep -En -A2 'Set initial Radarr 3D credentials status' |grep API |awk -F- '{print $1}')
}

# Function to reset the utility
# This will remove all saved text files and reset the check statuses to invalid
reset(){
  echo -e "${red}**WARNING!!!** This will reset ALL setup progress!${endColor}"
  echo -e "${ylw}Do you wish to continue?${endColor}"
  echo ''
  echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o):"
  read -r resetConfirmation
  echo ''
  if ! [[ "${resetConfirmation}" =~ ^(yes|y|no|n)$ ]]; then
    echo -e "${red}Please specify yes, y, no, or n.${endColor}"
  elif [[ "${resetConfirmation}" =~ ^(yes|y)$ ]]; then
    cleanup
    sed -i.bak "${plexCredsStatusLineNum} s/plexCredsStatus='[^']*'/plexCredsStatus='invalid'/" "${scriptname}"
    sed -i.bak "${sonarrURLStatusLineNum} s/sonarrURLStatus='[^']*'/sonarrURLStatus='invalid'/" "${scriptname}"
    sed -i.bak "${sonarrAPIKeyStatusLineNum} s/sonarrAPIKeyStatus='[^']*'/sonarrAPIKeyStatus='invalid'/" "${scriptname}"
    sed -i.bak "${tautulliURLStatusLineNum} s/tautulliURLStatus='[^']*'/tautulliURLStatus='invalid'/" "${scriptname}"
    sed -i.bak "${tautulliAPIKeyStatusLineNum} s/tautulliAPIKeyStatus='[^']*'/tautulliAPIKeyStatus='invalid'/" "${scriptname}"
    main_menu
  elif [[ "${resetConfirmation}" =~ ^(no|n)$ ]]; then
    main_menu
  fi
}

# Function to prompt user for Plex credentials or token
get_plex_creds() {
  echo 'Welcome to the MediaButler setup utility!'
  echo 'First thing we need are your Plex credentials so please choose from one of the following options:'
  echo ''
  echo '1) Plex Username & Password'
  echo '2) Plex Auth Token'
  echo ''
  read -rp 'Enter your option: ' plexCredsOption
  echo ''
  if [ "${plexCredsOption}" == '1' ]; then
    echo 'Please enter your Plex username:'
    read -r plexUsername
    echo ''
    echo 'Please enter your Plex password:'
    read -rs plexPassword
    #unset password;
    #while IFS= read -rs -n1 plexPassword; do
    #  if [[ -z "${plexPassword}" ]]; then
    #    echo
    #    break
    #  else
    #    echo -n '*'
    #    password+=${plexPassword}
    #  fi
    #done
    echo ''
  elif [ "${plexCredsOption}" == '2' ]; then
    echo 'Please enter your Plex token:'
    read -rs plexToken
    echo ''
  else
    echo 'You provided an invalid option, please try again.'
    exit 1
  fi
}

# Function to check that the provided Plex credentials are valid
check_plex_creds() {
  echo "Now we're going to make sure you provided valid credentials..."
  while [ "${plexCredsStatus}" = 'invalid' ]; do
    if [ "${plexCredsOption}" == '1' ]; then
      curl -s --location --request POST "${mbLoginURL}" \
      -H "${mbClientID}" \
      --data "username=${plexUsername}&password=${plexPassword}" |jq . > "${plexCredsFile}"
      authResponse=$(jq .name "${plexCredsFile}" |tr -d '"')
      if [[ "${authResponse}" =~ 'BadRequest' ]]; then
        echo -e "${red}The credentials that you provided are not valid!${endColor}"
        echo ''
        echo 'Please enter your Plex username:'
        read -r plexUsername
        echo 'Please enter your Plex password:'
        read -rs plexPassword
      elif [[ "${authResponse}" != *'BadRequest'* ]]; then
        sed -i.bak "${plexCredsStatusLineNum} s/plexCredsStatus='[^']*'/plexCredsStatus='ok'/" "${scriptname}"
        plexCredsStatus='ok'
        echo -e "${grn}Success!${endColor}"
        echo ''
      fi
    elif [ "${plexCredsOption}" == '2' ]; then
      curl -s --location --request POST "${mbLoginURL}" \
      -H "${mbClientID}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      --data "authToken=${plexToken}" |jq . > "${plexCredsFile}"
      authResponse=$(jq .name "${plexCredsFile}" |tr -d '"')
      if [[ "${authResponse}" =~ 'BadRequest' ]]; then
        echo -e "${red}The credentials that you provided are not valid!${endColor}"
        echo ''
        echo 'Please enter your Plex token:'
        read -rs plexToken
      elif [[ "${authResponse}" != *'BadRequest'* ]]; then
        sed -i.bak "${plexCredsStatusLineNum} s/plexCredsStatus='[^']*'/plexCredsStatus='ok'/" "${scriptname}"
        plexCredsStatus='ok'
      fi
    fi
  done
}

# Function to get user's Plex token
get_plex_token() {
  if [ "${plexCredsOption}" == '1' ]; then
    plexToken=$(curl -s -X "POST" "https://plex.tv/users/sign_in.json" \
      -H "X-Plex-Version: 1.0.0" \
      -H "X-Plex-Product: MediaButler" \
      -H "X-Plex-Client-Identifier: ${mbClientIDShort}" \
      -H "Content-Type: application/x-www-form-urlencoded; charset=utf-8" \
      --data-urlencode "user[password]=${plexPassword}" \
      --data-urlencode "user[login]=${plexUsername}" |jq .user.authToken |tr -d '"')
    echo "${plexToken}" > "${plexTokenFile}"
  elif [ "${plexCredsOption}" == '2' ]; then
    echo "${plexToken}" > "${plexTokenFile}"
  fi
}

# Function to create list of Plex servers
create_plex_servers_list() {
  jq .servers[].name "${plexCredsFile}" |tr -d '"' > "${plexServersFile}"
  IFS=$'\r\n' GLOBIGNORE='*' command eval 'plexServers=($(cat "${plexServersFile}"))'
  for ((i = 0; i < ${#plexServers[@]}; ++i)); do
    position=$(( $i + 1 ))
    echo "$position) ${plexServers[$i]}"
  done > "${numberedPlexServersFile}"
}

# Function to prompt user to select Plex Server from list and retrieve user's MediaButler URL
prompt_for_plex_server() {
  numberOfOptions=$(echo "${#plexServers[@]}")
  echo 'Please choose which Plex Server you would like to setup MediaButler for:'
  echo ''
  cat "${numberedPlexServersFile}"
  echo ''
  read -p "Server (1-${numberOfOptions}): " plexServerSelection
  echo ''
  echo 'Gathering required information...'
  plexServerArrayElement=$((${plexServerSelection}-1))
  selectedPlexServerName=$(jq .servers["${plexServerArrayElement}"].name "${plexCredsFile}" |tr -d '"')
  plexServerMachineID=$(jq .servers["${plexServerArrayElement}"].machineId "${plexCredsFile}" |tr -d '"')
  userMBURL=$(curl -s --location --request POST "${mbDiscoverURL}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "${mbClientID}" \
    --data "authToken=${plexToken}&machineId=${plexServerMachineID}")
  plexServerMBToken=$(jq .servers["${plexServerArrayElement}"].token "${plexCredsFile}" |tr -d '"')
  echo -e "${grn}Done!${endColor}"
  echo ''
  echo 'Is this the correct MediaButler URL?'
  echo -e "${ylw}${userMBURL}${endColor}"
  echo ''
  echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o):"
  read -r mbURLConfirmation
  echo ''
  if ! [[ "${mbURLConfirmation}" =~ ^(yes|y|no|n)$ ]]; then
    echo -e "${red}Please specify yes, y, no, or n.${endColor}"
  elif [[ "${mbURLConfirmation}" =~ ^(yes|y)$ ]]; then
    :
  elif [[ "${mbURLConfirmation}" =~ ^(no|n)$ ]]; then
    echo 'Please enter the correct MediaButler URL:'
    read -r userMBURL
  fi
  echo "${plexServerMachineID}" > "${plexServerMachineIDFile}"
  echo "${userMBURL}" > "${userMBURLFile}"
  echo "${plexServerMBToken}" > "${plexServerMBTokenFile}"
}

# Function to exit the menu
exit_menu() {
  echo -e "${red}This will exit the program and any unfinished config setup will be lost.${endColor}"
  echo -e "${ylw}Are you sure you wish to exit?${endColor}"
  echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o):"
  read -r exitPrompt
  if ! [[ "${exitPrompt}" =~ ^(yes|y|no|n)$ ]]; then
    echo -e "${red}Please specify yes, y, no, or n.${endColor}"
  elif [[ "${exitPrompt}" =~ ^(yes|y)$ ]]; then
    exit 0
  elif [[ "${exitPrompt}" =~ ^(no|n)$ ]]; then
    main_menu
  fi
}

# Function to make sure provided URLs have a trailing slash
convert_url() {
  if [[ "${providedURL: -1}" = '/' ]]; then
    convertedURL=$(echo "${providedURL}")
  elif [[ "${providedURL: -1}" != '/' ]]; then
    convertedURL=$(providedURL+=\/; echo "${providedURL}")
  fi
  JSONConvertedURL=$(echo "${providedURL}" |sed 's/:/%3A/g')
}

# Function to display the main menu
main_menu(){
  echo '*****************************************'
  echo '*               Main Menu               *'
  echo '*****************************************'
  echo 'Please choose which application you would'
  echo '   like to configure for MediaButler:    '
  echo ''
  echo '1) Sonarr'
  echo '2) Radarr'
  echo '3) Tautulli'
  echo '4) Reset'
  echo '5) Exit'
  echo ''
  read -rp 'Selection: ' mainMenuSelection
  echo ''
  if ! [[ "${mainMenuSelection}" =~ ^(1|2|3|4|5)$ ]]; then
    echo -e "${red}You did not specify a valid option!${endColor}"
    main_menu
  elif [ "${mainMenuSelection}" = '1' ]; then
    sonarr_menu
  elif [ "${mainMenuSelection}" = '2' ]; then
    radarr_menu
  elif [ "${mainMenuSelection}" = '3' ]; then
    setup_tautulli
  elif [ "${mainMenuSelection}" = '4' ]; then
    reset
  elif [ "${mainMenuSelection}" = '5' ]; then
    exit_menu
  fi
}

# Function to display the Sonarr sub-menu
sonarr_menu() {
  echo '*****************************************'
  echo '*           Sonarr Setup Menu           *'
  echo '*****************************************'
  echo 'Please choose which version of Sonarr you'
  echo 'would like to configure for MediaButler: '
  echo ''
  echo '1) Sonarr'
  echo '2) Sonarr 4K'
  echo '3) Back to Main Menu'
  echo ''
  read -rp 'Selection: ' sonarrMenuSelection
  echo ''
  if ! [[ "${sonarrMenuSelection}" =~ ^(1|2|3)$ ]]; then
    echo -e "${red}You did not specify a valid option!${endColor}"
    sonarr_menu
  elif [[ "${sonarrMenuSelection}" =~ ^(1|2)$ ]]; then
    setup_sonarr
  elif [ "${sonarrMenuSelection}" = '3' ]; then
    main_menu
  fi
}

# Function to display the Radarr sub-menu
radarr_menu() {
  echo '*****************************************'
  echo '*           Radarr Setup Menu           *'
  echo '*****************************************'
  echo 'Please choose which version of Radarr you'
  echo 'would like to configure for MediaButler: '
  echo ''
  echo '1) Radarr'
  echo '2) Radarr 4K'
  echo '3) Radarr 3D'
  echo '4) Back to Main Menu'
  echo ''
  read -rp 'Selection: ' radarrMenuSelection
  echo ''
  if ! [[ "${radarrMenuSelection}" =~ ^(1|2|3|4)$ ]]; then
    echo -e "${red}You did not specify a valid option!${endColor}"
    radarr_menu
  elif [[ "${radarrMenuSelection}" =~ ^(1|2|3)$ ]]; then
    setup_radarr
  elif [ "${radarrMenuSelection}" = '4' ]; then
    main_menu
  fi
}

# Function to create list of Sonarr/Radarr profiles
create_arr_profiles_list() {
  jq .[].name "${rawArrProfilesFile}" |tr -d '"' > "${arrProfilesFile}"
  IFS=$'\r\n' GLOBIGNORE='*' command eval 'arrProfiles=($(cat "${arrProfilesFile}"))'
  for ((i = 0; i < ${#arrProfiles[@]}; ++i)); do
    position=$(( $i + 1 ))
    echo "$position) ${arrProfiles[$i]}"
  done > "${numberedArrProfilesFile}"
}

# Function to prompt user for default Arr profile
prompt_for_arr_profile() {
  numberOfOptions=$(echo "${#arrProfiles[@]}")
  echo 'Please choose which profile you would like to set as the default for MediaButler:'
  echo ''
  cat "${numberedArrProfilesFile}"
  echo ''
  read -p "Profile (1-${numberOfOptions}):" arrProfilesSelection
  echo ''
  arrProfilesArrayElement=$((${arrProfilesSelection}-1))
  selectedArrProfile=$(jq .["${arrProfilesArrayElement}"].name "${rawArrProfilesFile}" |tr -d '"')
}

# Function to create list of Sonarr/Radarr root directories
create_arr_root_dirs_list() {
  jq .[].path "${rawArrRootDirsFile}" |tr -d '"' > "${arrRootDirsFile}"
  IFS=$'\r\n' GLOBIGNORE='*' command eval 'arrRootDirs=($(cat "${arrRootDirsFile}"))'
  for ((i = 0; i < ${#arrRootDirs[@]}; ++i)); do
    position=$(( $i + 1 ))
    echo "$position) ${arrRootDirs[$i]}"
  done > "${numberedArrRootDirsFile}"
}

# Function to prompt user for default Arr root directory
prompt_for_arr_root_dir() {
  numberOfOptions=$(echo "${#arrRootDirs[@]}")
  echo 'Please choose which root directory you would like to set as the default for MediaButler:'
  echo ''
  cat "${numberedArrRootDirsFile}"
  echo ''
  read -p "Root Dir (1-${numberOfOptions}):" arrRootDirsSelection
  echo ''
  arrRootDirsArrayElement=$((${arrRootDirsSelection}-1))
  selectedArrRootDir=$(jq .["${arrRootDirsArrayElement}"].path "${rawArrRootDirsFile}" |tr -d '"')
}

# Function to process Sonarr configuration
setup_sonarr() {
  if [ "${sonarrMenuSelection}" = '1' ]; then
    echo 'Please enter your Sonarr URL (IE: http://127.0.0.1:8989/sonarr/):'
    read -r providedURL
    echo ''
    echo 'Checking that the provided Sonarr URL is valid...'
    convert_url
    set +e
    sonarrURLCheckResponse=$(curl --head --write-out %{http_code} -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
    set -e
    while [ "${sonarrURLStatus}" = 'invalid' ]; do
      if [ "${sonarrURLCheckResponse}" = '200' ]; then
        sed -i.bak "${sonarrURLStatusLineNum} s/sonarrURLStatus='[^']*'/sonarrURLStatus='ok'/" "${scriptname}"
        sonarrURLStatus='ok'
        echo -e "${grn}Success!${endColor}"
        echo ''
      elif [ "${sonarrURLCheckResponse}" != '200' ]; then
        echo -e "${red}There was an error while attempting to validate the provided URL!${endColor}"
        echo 'Please enter your Sonarr URL (IE: http://127.0.0.1:8989/sonarr/):'
        read -r providedURL
        echo ''
        echo 'Checking that the provided Sonarr URL is valid...'
        convert_url
        set +e
        sonarrURLCheckResponse=$(curl --head --write-out %{http_code} -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
        set -e
      fi
    done
    echo 'Please enter your Sonarr API key:'
    read -r sonarrAPIKey
    echo ''
    echo 'Testing that the provided Sonarr API Key is valid...'
    echo ''
    sonarrAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${sonarrAPIKey}" |jq .[] |tr -d '"')
    while [ "${sonarrAPIKeyStatus}" = 'invalid' ]; do
      if [ "${sonarrAPITestResponse}" = 'Unauthorized' ]; then
        echo -e "${red}Received something other than an OK response!${endColor}"
        echo 'Please enter your Sonarr API Key:'
        read -r sonarrAPIKey
        echo ''
        sonarrAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${sonarrAPIKey}" |jq .[] |tr -d '"')
      elif [ "${sonarrAPITestResponse}" != 'Unauthorized' ]; then
        sed -i.bak "${sonarrAPIKeyStatusLineNum} s/sonarrAPIKeyStatus='[^']*'/sonarrAPIKeyStatus='ok'/" "${scriptname}"
        sonarrAPIKeyStatus='ok'
        echo -e "${grn}Success!${endColor}"
      fi
    done
    curl -s -X GET "${convertedURL}api/profile" -H "X-Api-Key: ${sonarrAPIKey}" |jq . > "${rawArrProfilesFile}"
    create_arr_profiles_list
    prompt_for_arr_profile
    curl -s -X GET "${convertedURL}api/rootfolder" -H "X-Api-Key: ${sonarrAPIKey}" |jq . > "${rawArrRootDirsFile}"
    create_arr_root_dirs_list
    prompt_for_arr_root_dir
    echo 'Testing the full Sonarr config for MediaButler...'
    curl -s --location --request PUT "${userMBURL}configure/sonarr?" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "${mbClientID}" \
    -H "Authorization: Bearer ${plexServerMBToken}" \
    --data "url=${JSONConvertedURL}&apikey=${sonarrAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${sonarrConfigFile}"
    sonarrMBConfigTestResponse=$(cat "${sonarrConfigFile}" |jq .message |tr -d '"')
    if [ "${sonarrMBConfigTestResponse}" = 'success' ]; then
      echo -e "${grn}Success!${endColor}"
      echo ''
      echo 'Saving the Sonarr config to MediaButler...'
      curl -s --location --request POST "${userMBURL}configure/sonarr?" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "${mbClientID}" \
      -H "Authorization: Bearer ${plexServerMBToken}" \
      --data "url=${JSONConvertedURL}&apikey=${sonarrAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${sonarrConfigFile}"
      sonarrMBConfigPostResponse=$(cat "${sonarrConfigFile}" |jq .message |tr -d '"')
      if [ "${sonarrMBConfigPostResponse}" = 'success' ]; then
        echo -e "${grn}Done! Sonarr has been successfully configured for${endColor}"
        echo -e "${grn}MediaButler with the ${selectedPlexServerName} Plex server.${endColor}"
        sleep 3
        echo ''
        echo 'Returning you to the Main Menu...'
        main_menu
      elif [ "${sonarrMBConfigPostResponse}" != 'success' ]; then
        echo -e "${red}Config push failed! Please try again later.${endColor}"
        sleep 3
        main_menu
      fi
    elif [ "${sonarrMBConfigTestResponse}" != 'success' ]; then
      echo -e "${red}Hmm, something weird happened. Please try again.${endColor}"
      sleep 3
      main_menu
    fi
  elif [ "${sonarrMenuSelection}" = '2' ]; then
    echo 'Please enter your Sonarr 4K URL (IE: http://127.0.0.1:8989/sonarr/):'
    read -r providedURL
    echo ''
    echo 'Checking that the provided Sonarr 4K URL is valid...'
    convert_url
    set +e
    sonarr4kURLCheckResponse=$(curl --head --write-out %{http_code} -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
    set -e
    while [ "${sonarr4kURLStatus}" = 'invalid' ]; do
      if [ "${sonarr4kURLCheckResponse}" = '200' ]; then
        sed -i.bak "${sonarr4kURLStatusLineNum} s/sonarr4kURLStatus='[^']*'/sonarr4kURLStatus='ok'/" "${scriptname}"
        sonarr4kURLStatus='ok'
        echo -e "${grn}Success!${endColor}"
        echo ''
      elif [ "${sonarr4kURLCheckResponse}" != '200' ]; then
        echo -e "${red}There was an error while attempting to validate the provided URL!${endColor}"
        echo 'Please enter your Sonarr 4k URL (IE: http://127.0.0.1:8989/sonarr/):'
        read -r providedURL
        echo ''
        echo 'Checking that the provided Sonarr 4k URL is valid...'
        convert_url
        set +e
        sonarr4kURLCheckResponse=$(curl --head --write-out %{http_code} -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
        set -e
      fi
    done
    echo 'Please enter your Sonarr 4K API key:'
    read -r sonarr4kAPIKey
    echo ''
    echo 'Testing that the provided Sonarr 4K API Key is valid...'
    echo ''
    sonarr4kAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${sonarr4kAPIKey}" |jq .[] |tr -d '"')
    while [ "${sonarr4kAPIKeyStatus}" = 'invalid' ]; do
      if [ "${sonarr4kAPITestResponse}" = 'Unauthorized' ]; then
        echo -e "${red}Received something other than an OK response!${endColor}"
        echo 'Please enter your Sonarr 4K API Key:'
        read -r sonarr4kAPIKey
        echo ''
        sonarr4kAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${sonarr4kAPIKey}" |jq .[] |tr -d '"')
      elif [ "${sonarr4kAPITestResponse}" != 'Unauthorized' ]; then
        sed -i.bak "${sonarr4kAPIKeyStatusLineNum} s/sonarr4kAPIKeyStatus='[^']*'/sonarr4kAPIKeyStatus='ok'/" "${scriptname}"
        sonarr4kAPIKeyStatus='ok'
        echo -e "${grn}Success!${endColor}"
      fi
    done
    curl -s -X GET "${convertedURL}api/profile" -H "X-Api-Key: ${sonarr4kAPIKey}" |jq . > "${rawArrProfilesFile}"
    create_arr_profiles_list
    prompt_for_arr_profile
    curl -s -X GET "${convertedURL}api/rootfolder" -H "X-Api-Key: ${sonarr4kAPIKey}" |jq . > "${rawArrRootDirsFile}"
    create_arr_root_dirs_list
    prompt_for_arr_root_dir
    echo 'Testing the full Sonarr 4K config for MediaButler...'
    curl -s --location --request PUT "${userMBURL}configure/sonarr4k?" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "${mbClientID}" \
    -H "Authorization: Bearer ${plexServerMBToken}" \
    --data "url=${JSONConvertedURL}&apikey=${sonarr4kAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${sonarr4kConfigFile}"
    sonarr4kMBConfigTestResponse=$(cat "${sonarr4kConfigFile}" |jq .message |tr -d '"')
    if [ "${sonarr4kMBConfigTestResponse}" = 'success' ]; then
      echo -e "${grn}Success!${endColor}"
      echo ''
      echo 'Saving the Sonarr 4K config to MediaButler...'
      curl -s --location --request POST "${userMBURL}configure/sonarr4k?" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "${mbClientID}" \
      -H "Authorization: Bearer ${plexServerMBToken}" \
      --data "url=${JSONConvertedURL}&apikey=${sonarr4kAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${sonarrConfigFile}"
      sonarr4kMBConfigPostResponse=$(cat "${sonarr4kConfigFile}" |jq .message |tr -d '"')
      if [ "${sonarr4kMBConfigPostResponse}" = 'success' ]; then
        echo -e "${grn}Done! Sonarr 4K has been successfully configured for${endColor}"
        echo -e "${grn}MediaButler with the ${selectedPlexServerName} Plex server.${endColor}"
        sleep 3
        echo ''
        echo 'Returning you to the Main Menu...'
        main_menu
      elif [ "${sonarr4kMBConfigPostResponse}" != 'success' ]; then
        echo -e "${red}Config push failed! Please try again later.${endColor}"
        sleep 3
        main_menu
      fi
    elif [ "${sonarr4kMBConfigTestResponse}" != 'success' ]; then
      echo -e "${red}Hmm, something weird happened. Please try again.${endColor}"
      sleep 3
      main_menu
    fi
  fi
}

# Function to process Radarr configuration
setup_radarr() {
  if [ "${radarrMenuSelection}" = '1' ]; then
    echo 'Please enter your Radarr URL (IE: http://127.0.0.1:8989/radarr/):'
    read -r providedURL
    echo ''
    echo 'Checking that the provided Radarr URL is valid...'
    convert_url
    set +e
    radarrURLCheckResponse=$(curl --head --write-out %{http_code} -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
    set -e
    while [ "${radarrURLStatus}" = 'invalid' ]; do
      if [ "${radarrURLCheckResponse}" = '200' ]; then
        sed -i.bak "${radarrURLStatusLineNum} s/radarrURLStatus='[^']*'/radarrURLStatus='ok'/" "${scriptname}"
        radarrURLStatus='ok'
        echo -e "${grn}Success!${endColor}"
        echo ''
      elif [ "${radarrURLCheckResponse}" != '200' ]; then
        echo -e "${red}There was an error while attempting to validate the provided URL!${endColor}"
        echo 'Please enter your Radarr URL (IE: http://127.0.0.1:8989/radarr/):'
        read -r providedURL
        echo ''
        echo 'Checking that the provided Radarr URL is valid...'
        convert_url
        set +e
        radarrURLCheckResponse=$(curl --head --write-out %{http_code} -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
        set -e
      fi
    done
    echo 'Please enter your Radarr API key:'
    read -r radarrAPIKey
    echo ''
    echo 'Testing that the provided Radarr API Key is valid...'
    echo ''
    radarrAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${radarrAPIKey}" |jq .[] |tr -d '"')
    while [ "${radarrAPIKeyStatus}" = 'invalid' ]; do
      if [ "${radarrAPITestResponse}" = 'Unauthorized' ]; then
        echo -e "${red}Received something other than an OK response!${endColor}"
        echo 'Please enter your Radarr API Key:'
        read -r radarrAPIKey
        echo ''
        radarrAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${radarrAPIKey}" |jq .[] |tr -d '"')
      elif [ "${radarrAPITestResponse}" != 'Unauthorized' ]; then
        sed -i.bak "${radarrAPIKeyStatusLineNum} s/radarrAPIKeyStatus='[^']*'/radarrAPIKeyStatus='ok'/" "${scriptname}"
        radarrAPIKeyStatus='ok'
        echo -e "${grn}Success!${endColor}"
      fi
    done
    curl -s -X GET "${convertedURL}api/profile" -H "X-Api-Key: ${radarrAPIKey}" |jq . > "${rawArrProfilesFile}"
    create_arr_profiles_list
    prompt_for_arr_profile
    curl -s -X GET "${convertedURL}api/rootfolder" -H "X-Api-Key: ${radarrAPIKey}" |jq . > "${rawArrRootDirsFile}"
    create_arr_root_dirs_list
    prompt_for_arr_root_dir
    echo 'Testing the full Radarr config for MediaButler...'
    curl -s --location --request PUT "${userMBURL}configure/radarr?" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "${mbClientID}" \
    -H "Authorization: Bearer ${plexServerMBToken}" \
    --data "url=${JSONConvertedURL}&apikey=${radarrAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${radarrConfigFile}"
    radarrMBConfigTestResponse=$(cat "${radarrConfigFile}" |jq .message |tr -d '"')
    if [ "${radarrMBConfigTestResponse}" = 'success' ]; then
      echo -e "${grn}Success!${endColor}"
      echo ''
      echo 'Saving the Radarr config to MediaButler...'
      curl -s --location --request POST "${userMBURL}configure/radarr?" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "${mbClientID}" \
      -H "Authorization: Bearer ${plexServerMBToken}" \
      --data "url=${JSONConvertedURL}&apikey=${radarrAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${radarrConfigFile}"
      radarrMBConfigPostResponse=$(cat "${radarrConfigFile}" |jq .message |tr -d '"')
      if [ "${radarrMBConfigPostResponse}" = 'success' ]; then
        echo -e "${grn}Done! Radarr has been successfully configured for${endColor}"
        echo -e "${grn}MediaButler with the ${selectedPlexServerName} Plex server.${endColor}"
        sleep 3
        echo ''
        echo 'Returning you to the Main Menu...'
        main_menu
      elif [ "${radarrMBConfigPostResponse}" != 'success' ]; then
        echo -e "${red}Config push failed! Please try again later.${endColor}"
        sleep 3
        main_menu
      fi
    elif [ "${radarrMBConfigTestResponse}" != 'success' ]; then
      echo -e "${red}Hmm, something weird happened. Please try again.${endColor}"
      sleep 3
      main_menu
    fi
  elif [ "${radarrMenuSelection}" = '2' ]; then
    echo 'Please enter your Radarr 4K URL (IE: http://127.0.0.1:8989/radarr/):'
    read -r providedURL
    echo ''
    echo 'Checking that the provided Radarr 4K URL is valid...'
    convert_url
    set +e
    radarr4kURLCheckResponse=$(curl --head --write-out %{http_code} -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
    set -e
    while [ "${radarr4kURLStatus}" = 'invalid' ]; do
      if [ "${radarr4kURLCheckResponse}" = '200' ]; then
        sed -i.bak "${radarr4kURLStatusLineNum} s/radarr4kURLStatus='[^']*'/radarr4kURLStatus='ok'/" "${scriptname}"
        radarr4kURLStatus='ok'
        echo -e "${grn}Success!${endColor}"
        echo ''
      elif [ "${radarr4kURLCheckResponse}" != '200' ]; then
        echo -e "${red}There was an error while attempting to validate the provided URL!${endColor}"
        echo 'Please enter your Radarr 4k URL (IE: http://127.0.0.1:8989/radarr/):'
        read -r providedURL
        echo ''
        echo 'Checking that the provided Radarr 4k URL is valid...'
        convert_url
        set +e
        radarr4kURLCheckResponse=$(curl --head --write-out %{http_code} -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
        set -e
      fi
    done
    echo 'Please enter your Radarr 4K API key:'
    read -r radarr4kAPIKey
    echo ''
    echo 'Testing that the provided Radarr 4K API Key is valid...'
    echo ''
    radarr4kAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${radarr4kAPIKey}" |jq .[] |tr -d '"')
    while [ "${radarr4kAPIKeyStatus}" = 'invalid' ]; do
      if [ "${radarr4kAPITestResponse}" = 'Unauthorized' ]; then
        echo -e "${red}Received something other than an OK response!${endColor}"
        echo 'Please enter your Radarr 4K API Key:'
        read -r radarr4kAPIKey
        echo ''
        radarr4kAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${radarr4kAPIKey}" |jq .[] |tr -d '"')
      elif [ "${radarr4kAPITestResponse}" != 'Unauthorized' ]; then
        sed -i.bak "${radarr4kAPIKeyStatusLineNum} s/radarr4kAPIKeyStatus='[^']*'/radarr4kAPIKeyStatus='ok'/" "${scriptname}"
        radarr4kAPIKeyStatus='ok'
        echo -e "${grn}Success!${endColor}"
      fi
    done
    curl -s -X GET "${convertedURL}api/profile" -H "X-Api-Key: ${radarr4kAPIKey}" |jq . > "${rawArrProfilesFile}"
    create_arr_profiles_list
    prompt_for_arr_profile
    curl -s -X GET "${convertedURL}api/rootfolder" -H "X-Api-Key: ${radarr4kAPIKey}" |jq . > "${rawArrRootDirsFile}"
    create_arr_root_dirs_list
    prompt_for_arr_root_dir
    echo 'Testing the full Radarr 4K config for MediaButler...'
    curl -s --location --request PUT "${userMBURL}configure/radarr4k?" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "${mbClientID}" \
    -H "Authorization: Bearer ${plexServerMBToken}" \
    --data "url=${JSONConvertedURL}&apikey=${radarr4kAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${radarr4kConfigFile}"
    radarr4kMBConfigTestResponse=$(cat "${radarr4kConfigFile}" |jq .message |tr -d '"')
    if [ "${radarr4kMBConfigTestResponse}" = 'success' ]; then
      echo -e "${grn}Success!${endColor}"
      echo ''
      echo 'Saving the Radarr 4K config to MediaButler...'
      curl -s --location --request POST "${userMBURL}configure/radarr4k?" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "${mbClientID}" \
      -H "Authorization: Bearer ${plexServerMBToken}" \
      --data "url=${JSONConvertedURL}&apikey=${radarr4kAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${radarrConfigFile}"
      radarr4kMBConfigPostResponse=$(cat "${radarr4kConfigFile}" |jq .message |tr -d '"')
      if [ "${radarr4kMBConfigPostResponse}" = 'success' ]; then
        echo -e "${grn}Done! Radarr 4K has been successfully configured for${endColor}"
        echo -e "${grn}MediaButler with the ${selectedPlexServerName} Plex server.${endColor}"
        sleep 3
        echo ''
        echo 'Returning you to the Main Menu...'
        main_menu
      elif [ "${radarr4kMBConfigPostResponse}" != 'success' ]; then
        echo -e "${red}Config push failed! Please try again later.${endColor}"
        sleep 3
        main_menu
      fi
    elif [ "${radarr4kMBConfigTestResponse}" != 'success' ]; then
      echo -e "${red}Hmm, something weird happened. Please try again.${endColor}"
      sleep 3
      main_menu
    fi
  elif [ "${radarrMenuSelection}" = '3' ]; then
    foo
  fi
}

# Function to process Tautulli configuration
setup_tautulli() {
  echo 'Please enter your Tautulli URL (IE: http://127.0.0.1:8181/tautulli/):'
  read -r providedURL
  echo ''
  echo 'Checking that the provided Tautulli URL is valid...'
  convert_url
  set +e
  tautulliURLCheckResponse=$(curl --head --write-out %{http_code} -sI --output /dev/null --connect-timeout 10 "${convertedURL}"auth/login)
  set -e
  while [ "${tautulliURLStatus}" = 'invalid' ]; do
    if [ "${tautulliURLCheckResponse}" = '200' ]; then
      sed -i.bak "${tautulliURLStatusLineNum} s/tautulliURLStatus='[^']*'/tautulliURLStatus='ok'/" "${scriptname}"
      tautulliURLStatus='ok'
      echo -e "${grn}Success!${endColor}"
      echo ''
    elif [ "${tautulliURLCheckResponse}" != '200' ]; then
      echo -e "${red}There was an error while attempting to validate the provided URL!${endColor}"
      echo 'Please enter your Tautulli URL (IE: http://127.0.0.1:8181/tautulli/):'
      read -r providedURL
      echo ''
      echo 'Checking that the provided Tautulli URL is valid...'
      convert_url
      set +e
      tautulliURLCheckResponse=$(curl --head --write-out %{http_code} -sI --output /dev/null --connect-timeout 10 "${convertedURL}"auth/login)
      set -e
    fi
  done
  echo 'Please enter your Tautulli API key:'
  read -r tautulliAPIKey
  echo ''
  echo 'Testing that the provided Tautulli API Key is valid...'
  echo ''
  tautulliAPITestResponse=$(curl -s "${convertedURL}api/v2?apikey=${tautulliAPIKey}&cmd=arnold" |jq .response.message |tr -d '"')
  while [ "${tautulliAPIKeyStatus}" = 'invalid' ]; do
    if [ "${tautulliAPITestResponse}" = 'null' ]; then
      sed -i.bak "${tautulliAPIKeyStatusLineNum} s/tautulliAPIKeyStatus='[^']*'/tautulliAPIKeyStatus='ok'/" "${scriptname}"
      tautulliAPIKeyStatus='ok'
      echo -e "${grn}Success!${endColor}"
      echo ''
    elif [ "${tautulliAPITestResponse}" = 'Invalid apikey' ]; then
      echo -e "${red}Received something other than an OK response!${endColor}"
      echo 'Please enter your Tautulli API Key:'
      read -r tautulliAPIKey
      echo ''
      tautulliAPITestResponse=$(curl -s "${convertedURL}api/v2?apikey=${tautulliAPIKey}&cmd=arnold" |jq .response.message |tr -d '"')
    fi
  done
  echo 'Testing the full Tautulli config for MediaButler...'
  curl -s --location --request PUT "${userMBURL}configure/tautulli?" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "${mbClientID}" \
  -H "Authorization: Bearer ${plexServerMBToken}" \
  --data "url=${JSONConvertedURL}&apikey=${tautulliAPIKey}" |jq . > "${tautulliConfigFile}"
  tautulliMBConfigTestResponse=$(cat "${tautulliConfigFile}" |jq .message |tr -d '"')
  if [ "${tautulliMBConfigTestResponse}" = 'success' ]; then
    echo -e "${grn}Success!${endColor}"
    echo ''
    echo 'Saving the Tautulli config to MediaButler...'
    curl -s --location --request POST "${userMBURL}configure/tautulli?" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "${mbClientID}" \
    -H "Authorization: Bearer ${plexServerMBToken}" \
    --data "url=${JSONConvertedURL}&apikey=${tautulliAPIKey}" |jq . > "${tautulliConfigFile}"
    tautulliMBConfigPostResponse=$(cat "${tautulliConfigFile}" |jq .message |tr -d '"')
    if [ "${tautulliMBConfigPostResponse}" = 'success' ]; then
      echo -e "${grn}Done! Tautulli has been successfully configured for${endColor}"
      echo -e "${grn}MediaButler with the ${selectedPlexServerName} Plex server.${endColor}"
      sleep 3
      echo ''
      echo 'Returning you to the Main Menu...'
      main_menu
    elif [ "${tautulliMBConfigPostResponse}" != 'success' ]; then
      echo -e "${red}Config push failed! Please try again later.${endColor}"
      sleep 3
      main_menu
    fi
  elif [ "${tautulliMBConfigTestResponse}" != 'success' ]; then
    echo -e "${red}Hmm, something weird happened. Please try again.${endColor}"
    sleep 3
    main_menu
  fi
}

# Main function to run all functions
main() {
  checks
  create_dir
  get_line_numbers
  if [[ -e "${plexCredsFile}" ]]; then
    sed -i.bak "${plexCredsStatusLineNum} s/plexCredsStatus='[^']*'/plexCredsStatus='ok'/" "${scriptname}"
  elif [[ ! -f "${plexCredsFile}" ]]; then
    get_plex_creds
    check_plex_creds
  fi
  if [[ -e "${plexTokenFile}" ]]; then
    plexToken=$(cat "${plexTokenFile}")
  elif [[ ! -f "${plexTokenFile}" ]]; then
    get_plex_token
  fi
  if [[ -e "${plexServersFile}" ]]; then
    plexServerMachineID=$(cat "${plexServerMachineIDFile}")
    userMBURL=$(cat "${userMBURLFile}")
    plexServerMBToken=$(cat "${plexServerMBTokenFile}")
  elif [[ ! -f "${plexServersFile}" ]]; then
    create_plex_servers_list
    prompt_for_plex_server
  fi
  main_menu
}

main

