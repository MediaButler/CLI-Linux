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
plexCredsStatus='invalid'
# Set initial Plex server selection status
plexServerStatus='invalid'
# Set initial MediaButler URL status
mbURLStatus='invalid'
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
radarrURLStatus='invalid'
radarrAPIKeyStatus='invalid'
# Set initial Radarr 4K credentials status
radarr4kURLStatus='invalid'
radarr4kAPIKeyStatus='invalid'
# Set initial Radarr 3D credentials status
radarr3dURLStatus='invalid'
radarr3dAPIKeyStatus='invalid'

# Define temp dir and files
tempDir='/tmp/mb_setup/'
plexCredsFile="${tempDir}plex_creds_check.txt"
envFile="${tempDir}envFile.txt"
jsonEnvFile='data.json'
plexTokenFile="${tempDir}plex_token.txt"
#plexServerMachineIDFile="${tempDir}plex_machineID.txt"
#selectedPlexServerNameFile="${tempDir}plex_server_name.txt"
#userMBURLFile="${tempDir}user_mb_url.txt"
#plexServerMBTokenFile="${tempDir}plex_server_mb_token.txt"
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
radarr4kConfigFile="${tempDir}radarr4k_config.txt"
radarr3dConfigFile="${tempDir}radarr3d_config.txt"

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
  bashMajorVersion=$(bash --version |head -1 |awk '{print $4}' |cut -c1)
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
  wget -q -O "${tempDir}"pacapt https://github.com/icy/pacapt/raw/ng/pacapt
  chmod 755 "${tempDir}"pacapt
  declare -A osInfo;
  osInfo[/etc/redhat-release]='yum -y -q'
  osInfo[/etc/arch-release]=pacman
  osInfo[/etc/gentoo-release]=emerge
  osInfo[/etc/SuSE-release]=zypp
  osInfo[/etc/debian_version]='apt -y -qq'
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
  set +e
  whichCURL=$(which curl)
  if [ -z "${whichCURL}" ]; then
    echo -e "${red}cURL is not currently installed!${endColor}"
    echo -e "${ylw}Doing it for you now...${endColor}"
    "${tempDir}"pacapt install curl
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
  set -e
}

# Function to check if JQ is installed and, if not, install it
check_jq() {
  set +e
  whichJQ=$(which jq)
  if [ -z "${whichJQ}" ]; then
    echo -e "${red}JQ is not currently installed!${endColor}"
    echo -e "${ylw}Doing it for you now...${endColor}"
    "${tempDir}"pacapt install jq
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
  set -e
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
  rm -rf "${tempDir}"/*.txt || true
  rm -rf "${scriptname}"*.bak || true
  rm -rf "${jsonEnvFile}" || true
}
trap 'cleanup' 0 1 3 6 14 15

# Exit the script if the user hits CTRL+C
function control_c() {
  cleanup
  if [ "${endpoint}" = 'plex' ]; then
    reset_plex
  elif [ "${endpoint}" = 'sonarr' ]; then
    reset_sonarr
  elif [ "${endpoint}" = 'sonarr4k' ]; then
    reset_sonarr4k
  elif [ "${endpoint}" = 'radarr' ]; then
    reset_radarr
  elif [ "${endpoint}" = 'radarr4k' ]; then
    reset_radarr4k
  elif [ "${endpoint}" = 'radarr3d' ]; then
    reset_radar3d
  fi
  exit
}
trap 'control_c' 2

# Grab status variable line numbers
get_line_numbers() {
  plexCredsStatusLineNum=$(head -50 "${scriptname}" |grep -En -A1 'Set initial Plex credentials status' |tail -1 | awk -F- '{print $1}')
  plexServerStatusLineNum=$(head -50 "${scriptname}" |grep -En -A1 'Set initial Plex server selection status' |tail -1 | awk -F- '{print $1}')
  mbURLStatusLineNum=$(head -50 "${scriptname}" |grep -En -A1 'Set initial MediaButler URL status' |tail -1 | awk -F- '{print $1}')
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

# Functions to reset the config status for the applications
# Plex
reset_plex() {
  sed -i.bak "${plexCredsStatusLineNum} s/plexCredsStatus='[^']*'/plexCredsStatus='invalid'/" "${scriptname}"
  plexCredsStatus='invalid'
  sed -i.bak "${plexServerStatusLineNum} s/plexServerStatus='[^']*'/plexServerStatus='invalid'/" "${scriptname}"
  plexServerStatus='invalid'
  sed -i.bak "${mbURLStatusLineNum} s/mbURLStatus='[^']*'/mbURLStatus='invalid'/" "${scriptname}"
  mbURLStatus='invalid'
}
# Sonarr
reset_sonarr() {
  sed -i.bak "${sonarrURLStatusLineNum} s/sonarrURLStatus='[^']*'/sonarrURLStatus='invalid'/" "${scriptname}"
  sonarrURLStatus='invalid'
  sed -i.bak "${sonarrAPIKeyStatusLineNum} s/sonarrAPIKeyStatus='[^']*'/sonarrAPIKeyStatus='invalid'/" "${scriptname}"
  sonarrAPIKeyStatus='invalid'
}
# Sonarr 4K
reset_sonarr4k() {
  sed -i.bak "${sonarr4kURLStatusLineNum} s/sonarr4kURLStatus='[^']*'/sonarr4kURLStatus='invalid'/" "${scriptname}"
  sonarr4kURLStatus='invalid'
  sed -i.bak "${sonarr4kAPIKeyStatusLineNum} s/sonarr4kAPIKeyStatus='[^']*'/sonarr4kAPIKeyStatus='invalid'/" "${scriptname}"
  sonarr4kAPIKeyStatus='invalid'
}
# Radarr
reset_radarr() {
  sed -i.bak "${radarrURLStatusLineNum} s/radarrURLStatus='[^']*'/radarrURLStatus='invalid'/" "${scriptname}"
  radarrURLStatus='invalid'
  sed -i.bak "${radarrAPIKeyStatusLineNum} s/radarrAPIKeyStatus='[^']*'/radarrAPIKeyStatus='invalid'/" "${scriptname}"
  radarrAPIKeyStatus='invalid'
}
# Radarr 4K
reset_radarr4k() {
  sed -i.bak "${radarr4kURLStatusLineNum} s/radarr4kURLStatus='[^']*'/radarr4kURLStatus='invalid'/" "${scriptname}"
  radarr4kURLStatus='invalid'
  sed -i.bak "${radarr4kAPIKeyStatusLineNum} s/radarr4kAPIKeyStatus='[^']*'/radarr4kAPIKeyStatus='invalid'/" "${scriptname}"
  radarr4kAPIKeyStatus='invalid'
}
# Radarr 3D
reset_radarr3d() {
  sed -i.bak "${radarr3dURLStatusLineNum} s/radarr3dURLStatus='[^']*'/radarr3dURLStatus='invalid'/" "${scriptname}"
  radarr3dURLStatus='invalid'
  sed -i.bak "${radarr3dAPIKeyStatusLineNum} s/radarr3dAPIKeyStatus='[^']*'/radarr3dAPIKeyStatus='invalid'/" "${scriptname}"
  radarr3dAPIKeyStatus='invalid'
}
# Tautulli
reset_tautulli() {
  sed -i.bak "${tautulliURLStatusLineNum} s/tautulliURLStatus='[^']*'/tautulliURLStatus='invalid'/" "${scriptname}"
  sed -i.bak "${tautulliAPIKeyStatusLineNum} s/tautulliAPIKeyStatus='[^']*'/tautulliAPIKeyStatus='invalid'/" "${scriptname}"
}
# All apps and Plex
reset(){
  echo -e "${red}**WARNING!!!** This will reset ALL setup progress!${endColor}"
  echo -e "${ylw}Do you wish to continue?${endColor}"
  echo ''
  echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o:"
  read -r resetConfirmation
  echo ''
  if ! [[ "${resetConfirmation}" =~ ^(yes|y|Yes|Y|no|n|No|N)$ ]]; then
    echo -e "${red}Please specify yes, y, no, or n.${endColor}"
  elif [[ "${resetConfirmation}" =~ ^(yes|y|Yes|Y)$ ]]; then
    reset_plex
    reset_sonarr
    reset_sonarr4k
    reset_radarr
    reset_radarr4k
    reset_radarr3d
    reset_tautulli
    cleanup
    exit 0
  elif [[ "${resetConfirmation}" =~ ^(no|n|No|N)$ ]]; then
    main_menu
  fi
}

# Function to prompt user for Plex credentials or token
get_plex_creds() {
  endpoint='plex'
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
    echo ''
  elif [ "${plexCredsOption}" == '2' ]; then
    echo 'Please enter your Plex token:'
    read -rs plexToken
    echo ''
  else
    echo 'You provided an invalid option, please try again.'
    reset_plex
    exit 1
  fi
}

# Function to check that the provided Plex credentials are valid
check_plex_creds() {
  endpoint='plex'
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
        echo ''
        echo 'Please enter your Plex password:'
        read -rs plexPassword
        echo ''
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
        echo ''
      elif [[ "${authResponse}" != *'BadRequest'* ]]; then
        sed -i.bak "${plexCredsStatusLineNum} s/plexCredsStatus='[^']*'/plexCredsStatus='ok'/" "${scriptname}"
        plexCredsStatus='ok'
        echo -e "${grn}Success!${endColor}"
        echo ''
      fi
    fi
  done
}

# Function to get user's Plex token
get_plex_token() {
  endpoint='plex'
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
  else
    :
  fi
}

# Function to create list of Plex servers
create_plex_servers_list() {
  endpoint='plex'
  jq '.servers[] | select(.owner==true)' "${plexCredsFile}" |jq .name |tr -d '"' > "${plexServersFile}"
  plexServers=''
  IFS=$'\r\n' GLOBIGNORE='*' command eval 'plexServers=($(cat "${plexServersFile}"))'
  for ((i = 0; i < ${#plexServers[@]}; ++i)); do
    position=$(( $i + 1 ))
    echo "$position) ${plexServers[$i]}"
  done > "${numberedPlexServersFile}"
}

# Function to prompt user to select Plex Server from list and retrieve user's MediaButler URL
prompt_for_plex_server() {
  endpoint='plex'
  numberOfOptions=$(echo "${#plexServers[@]}")
  while [ "${plexServerStatus}" = 'invalid' ]; do
    echo 'Please choose which Plex Server you would like to setup MediaButler for:'
    echo ''
    cat "${numberedPlexServersFile}"
    echo ''
    read -p "Server: " plexServerSelection
    if [[ "${plexServerSelection}" -lt '1' ]] || [[ "${plexServerSelection}" -gt "${numberOfOptions}" ]]; then
      echo -e "${red}You did not specify a valid option!${endColor}"
      reset_plex
    else
      sed -i.bak "${plexServerStatusLineNum} s/plexServerStatus='[^']*'/plexServerStatus='ok'/" "${scriptname}"
      plexServerStatus='ok'
    fi
  done
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
  echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o:"
  read -r mbURLConfirmation
  echo ''
  if ! [[ "${mbURLConfirmation}" =~ ^(yes|y|Yes|Y|no|n|No|N)$ ]]; then
    echo -e "${red}Please specify yes, y, no, or n.${endColor}"
  elif [[ "${mbURLConfirmation}" =~ ^(yes|y|Yes|Y)$ ]]; then
    :
  elif [[ "${mbURLConfirmation}" =~ ^(no|n|No|N)$ ]]; then
    echo 'Please enter the correct MediaButler URL:'
    read -r providedURL
    echo ''
    echo 'Checking that the provided MediaButler URL is valid...'
    echo ''
    convert_url
    set +e
    mbURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
    userMBApiVersionOne=$(curl -s --connect-timeout 10 "${convertedURL}"version |jq .apiVersion |tr -d '"' |awk -F '.' '{print $1}')
    userMBApiVersionTwo=$(curl -s --connect-timeout 10 "${convertedURL}"version |jq .apiVersion |tr -d '"' |awk -F '.' '{print $2}')
    userMBApiVersionThree=$(curl -s --connect-timeout 10 "${convertedURL}"version |jq .apiVersion |tr -d '"' |awk -F '.' '{print $3}')
    set -e
    if [[ "${userMBApiVersionOne}" -ge '1' ]] && [[ "${userMBApiVersionTwo}" -ge '1' ]] && [[ "${userMBApiVersionThree}" -ge '12' ]]; then
      mbAPIStatus='ok'
    else
      mbAPIStatus='bad'
    fi
    while [ "${mbURLStatus}" = 'invalid' ]; do
      if [[ "${mbURLCheckResponse}" = '200' ]] && [[ "${mbAPIStatus}" = 'ok' ]]; then
        sed -i.bak "${mbURLStatusLineNum} s/mbURLStatus='[^']*'/mbURLStatus='ok'/" "${scriptname}"
        mbURLStatus='ok'
        userMBURL=$(echo "${convertedURL}")
        echo -e "${grn}Success!${endColor}"
        echo ''
      elif [[ "${mbURLCheckResponse}" != '200' ]]; then
        echo -e "${red}There was an error while attempting to validate the provided URL!${endColor}"
        echo 'Please enter the correct MediaButler URL:'
        read -r providedURL
        echo ''
        echo 'Checking that the provided MediaButler URL is valid...'
        echo ''
        convert_url
        set +e
        mbURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
        set -e
      elif [[ "${mbAPIStatus}" = 'bad' ]]; then
        echo -e "${red}The version of the API that you're running appears to be out of date!${endColor}"
        echo -e "${org}Please update your MediaButler installation before continuing.${endColor}"
        exit 0
      fi
    done
  fi
}

# Function to create environment variables file
create_env_file() {
  echo "plexToken	${plexToken}" > "${envFile}"
  echo "serverName	${selectedPlexServerName}" >> "${envFile}"
  echo "mbToken	${plexServerMBToken}" >> "${envFile}"
  echo "machineId	${plexServerMachineID}" >> "${envFile}"
  echo "mbURL	${userMBURL}" >> "${envFile}"
  jq '. | split("\n") | map( split("\t") | {name: .[0], value: .[1]} ) | {data: .} ' -R -s "${envFile}" > "${jsonEnvFile}"
}

# Function to check if endpoints are already configured
#check_endpoints() {
#  mbEndpoints=(tautulli sonarr sonarr4k radarr radarr4k radarr3d)
#  for endpoint in "${mbEndpoints[@]}"; do
#    endpointStatus=$(curl -s --location --request GET "${userMBURL}configure/${endpoint}?" \
#    -H 'Content-Type: application/x-www-form-urlencoded' \
#    -H "${mbClientID}" \
#    -H "Authorization: Bearer ${plexServerMBToken}" |jq .settings)
#    checkURLStatusVar=${endpoint}'URLStatus'
#    checkAPIStatusVar=${endpoint}'APIStatus'
#    endpointConfiguredVar=${endpoint}'Configured'
#    if [[ "${!checkURLStatusVar}" = 'ok' ]] && [[ "${!checkAPIStatusVar}" = 'ok' ]] && [[ "${endpointStatus}" != '{}' ]]; then
#      declare -g "$(echo "${endpointConfiguredVar}")"='true'
#    elif [[ "${!checkURLStatusVar}" = 'invalid' ]] || [[ "${!checkAPIStatusVar}" = 'invalid' ]] || [[ "${endpointStatus}" = '{}' ]]; then
#      declare -g "$(echo "${endpointConfiguredVar}")"='false'
#    fi
#    endpointURL="configure/${endpoint}"
#  done
#}

# Function to exit the menu
exit_menu() {
  echo -e "${red}This will exit the program and any unfinished config setup will be lost.${endColor}"
  echo -e "${ylw}Are you sure you wish to exit?${endColor}"
  echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o:"
  read -r exitPrompt
  if ! [[ "${exitPrompt}" =~ ^(yes|y|Yes|Y|no|n|No|N)$ ]]; then
    echo -e "${red}Please specify yes, y, no, or n.${endColor}"
  elif [[ "${exitPrompt}" =~ ^(yes|y|Yes|Y)$ ]]; then
    exit 0
  elif [[ "${exitPrompt}" =~ ^(no|n|No|N)$ ]]; then
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
  if [[ "${sonarrURLStatus}" = 'ok' ]] && [[ "${sonarrAPIKeyStatus}" = 'ok' ]] && [[ "${sonarr4kURLStatus}" = 'ok' ]] && [[ "${sonarr4kAPIKeyStatus}" = 'ok' ]]; then
    echo -e "1) ${grn}Sonarr${endColor}"
  else
    echo '1) Sonarr'
  fi
  if [[ "${radarrURLStatus}" = 'ok' ]] && [[ "${radarrAPIKeyStatus}" = 'ok' ]] && [[ "${radarr4kURLStatus}" = 'ok' ]] && [[ "${radarr4kAPIKeyStatus}" = 'ok' ]] && [[ "${radarr3dURLStatus}" = 'ok' ]] && [[ "${radarr3dAPIKeyStatus}" = 'ok' ]]; then
    echo -e "1) ${grn}Sonarr${endColor}"
  else
    echo '2) Radarr'
  fi
  if [[ "${tautulliURLStatus}" = 'ok' ]] && [[ "${tautulliAPIKeyStatus}" = 'ok' ]]; then
    echo -e "3) ${grn}Tautulli${endColor}"
  else
    echo -e "3) ${red}Tautulli${endColor}"
  fi
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
  if [[ "${sonarrURLStatus}" = 'ok' ]] && [[ "${sonarrAPIKeyStatus}" = 'ok' ]]; then
    echo -e "1) ${grn}Sonarr${endColor}"
  else
    echo -e "1) ${red}Sonarr${endColor}"
  fi
  if [[ "${sonarr4kURLStatus}" = 'ok' ]] && [[ "${sonarr4kAPIKeyStatus}" = 'ok' ]]; then
    echo -e "2) ${grn}Sonarr 4K${endColor}"
  else
    echo -e "2) ${red}Sonarr 4K${endColor}"
  fi
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
  if [[ "${radarrURLStatus}" = 'ok' ]] && [[ "${radarrAPIKeyStatus}" = 'ok' ]]; then
    echo -e "1) ${grn}Radarr${endColor}"
  else
    echo -e "1) ${red}Radarr${endColor}"
  fi
  if [[ "${radarr4kURLStatus}" = 'ok' ]] && [[ "${radarr4kAPIKeyStatus}" = 'ok' ]]; then
    echo -e "2) ${grn}Radarr 4K${endColor}"
  else
    echo -e "2) ${red}Radarr 4K${endColor}"
  fi
  if [[ "${radarr3dURLStatus}" = 'ok' ]] && [[ "${radarr3dAPIKeyStatus}" = 'ok' ]]; then
    echo -e "3) ${grn}Radarr 3D${endColor}"
  else
    echo -e "3) ${red}Radarr 3D${endColor}"
  fi
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
  arrProfiles=''
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
  read -p "Profile (1-${numberOfOptions}): " arrProfilesSelection
  echo ''
  if [[ "${arrProfilesSelection}" -lt '1' ]] || [[ "${arrProfilesSelection}" -gt "${numberOfOptions}" ]]; then
    echo -e "${red}You didn't not specify a valid option!${endColor}"
    echo ''
    if [ "${endpoint}" = 'sonarr' ]; then
      reset_sonarr
      sonarr_menu
    elif [ "${endpoint}" = 'sonarr4k' ]; then
      reset_sonarr4k
      sonarr_menu
    elif [ "${endpoint}" = 'radarr' ]; then
      reset_radarr
      radarr_menu
    elif [ "${endpoint}" = 'radarr4k' ]; then
      reset_radarr4k
      radarr_menu
    elif [ "${endpoint}" = 'radarr3d' ]; then
      reset_radar3d
      radarr_menu
    fi
  else
    arrProfilesArrayElement=$((${arrProfilesSelection}-1))
    selectedArrProfile=$(jq .["${arrProfilesArrayElement}"].name "${rawArrProfilesFile}" |tr -d '"')
  fi
}

# Function to create list of Sonarr/Radarr root directories
create_arr_root_dirs_list() {
  jq .[].path "${rawArrRootDirsFile}" |tr -d '"' > "${arrRootDirsFile}"
  arrRootDirs=''
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
  read -p "Root Dir (1-${numberOfOptions}): " arrRootDirsSelection
  echo ''
  if [[ "${arrRootDirsSelection}" -lt '1' ]] || [[ "${arrRootDirsSelection}" -gt "${numberOfOptions}" ]]; then
    echo -e "${red}You didn't not specify a valid option!${endColor}"
    echo ''
    if [ "${endpoint}" = 'sonarr' ]; then
      reset_sonarr
      sonarr_menu
    elif [ "${endpoint}" = 'sonarr4k' ]; then
      reset_sonarr4k
      sonarr_menu
    elif [ "${endpoint}" = 'radarr' ]; then
      reset_radarr
      radarr_menu
    elif [ "${endpoint}" = 'radarr4k' ]; then
      reset_radarr4k
      radarr_menu
    elif [ "${endpoint}" = 'radarr3d' ]; then
      reset_radar3d
      radarr_menu
    fi
  else
    arrRootDirsArrayElement=$((${arrRootDirsSelection}-1))
    selectedArrRootDir=$(jq .["${arrRootDirsArrayElement}"].path "${rawArrRootDirsFile}" |tr -d '"')
  fi
}

# Function to process Sonarr configuration
setup_sonarr() {
  if [ "${sonarrMenuSelection}" = '1' ]; then
    endpoint='sonarr'
    if [[ "${sonarrURLStatus}" = 'ok' ]] && [[ "${sonarrAPIKeyStatus}" = 'ok' ]]; then
      sonarrSetupCheck=$(curl -s --location --request GET "${userMBURL}configure/${endpoint}?" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -H "${mbClientID}" \
      -H "Authorization: Bearer ${plexServerMBToken}" |jq .settings)
      if [ "${sonarrSetupCheck}" != '{}' ]; then
        echo -e "${red}Sonarr appears to be setup already!${endColor}"
        echo -e "${ylw}Do you wish to continue?${endColor}"
        echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o:"
        read -r continuePrompt
        if ! [[ "${continuePrompt}" =~ ^(yes|y|Yes|Y|no|n|No|N)$ ]]; then
          echo -e "${red}Please specify yes, y, no, or n.${endColor}"
        elif [[ "${continuePrompt}" =~ ^(yes|y|Yes|Y)$ ]]; then
          sed -i.bak "${sonarrURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='invalid'/" "${scriptname}"
          sonarrURLStatus='invalid'
          sed -i.bak "${sonarrAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='invalid'/" "${scriptname}"
          sonarrAPIKeyStatus='invalid'
        elif [[ "${continuePrompt}" =~ ^(no|n|No|N)$ ]]; then
          sonarr_menu
        fi
      elif [ "${sonarrSetupCheck}" = '{}' ]; then
        :
      fi
    elif [[ "${sonarrURLStatus}" = 'invalid' ]] || [[ "${sonarrAPIKeyStatus}" = 'invalid' ]]; then
      :
    fi
    #if [ "${sonarrConfigured}" = 'true' ]; then
    #  echo -e "${red}Sonarr appears to be setup already!${endColor}"
    #  echo -e "${ylw}Do you wish to continue?${endColor}"
    #  echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o:"
    #  read -r continuePrompt
    #  if ! [[ "${continuePrompt}" =~ ^(yes|y|no|n)$ ]]; then
    #    echo -e "${red}Please specify yes, y, no, or n.${endColor}"
    #  elif [[ "${continuePrompt}" =~ ^(yes|y)$ ]]; then
    #    sed -i.bak "${sonarrURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='invalid'/" "${scriptname}"
    #    sonarrURLStatus='invalid'
    #    sed -i.bak "${sonarrAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='invalid'/" "${scriptname}"
    #    sonarrAPIKeyStatus='invalid'
    #  elif [[ "${continuePrompt}" =~ ^(no|n)$ ]]; then
    #    sonarr_menu
    #  fi
    #elif [ "${sonarrConfigured}" = 'false' ]; then
    #  :
    #fi
    echo 'Please enter your Sonarr URL (IE: http://127.0.0.1:8989/sonarr/):'
    read -r providedURL
    echo ''
    echo 'Checking that the provided Sonarr URL is valid...'
    echo ''
    convert_url
    set +e
    sonarrURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
    sonarrURLAppCheckResponse=$(curl -s --connect-timeout 10 "${convertedURL}" |grep '<title>' |awk '{print $1}' |cut -c8-13)
    set -e
    while [ "${sonarrURLStatus}" = 'invalid' ]; do
      if [[ "${sonarrURLCheckResponse}" = '200' ]] && [[ "${sonarrURLAppCheckResponse}" = 'Sonarr' ]]; then
        sed -i.bak "${sonarrURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='ok'/" "${scriptname}"
        sonarrURLStatus='ok'
        echo -e "${grn}Success!${endColor}"
        echo ''
      elif [[ "${sonarrURLCheckResponse}" != '200' ]] || [[ "${sonarrURLAppCheckResponse}" != 'Sonarr' ]]; then
        echo -e "${red}There was an error while attempting to validate the provided URL!${endColor}"
        echo 'Please enter your Sonarr URL (IE: http://127.0.0.1:8989/sonarr/):'
        read -r providedURL
        echo ''
        echo 'Checking that the provided Sonarr URL is valid...'
        echo ''
        convert_url
        set +e
        sonarrURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
        sonarrURLAppCheckResponse=$(curl -s --connect-timeout 10 "${convertedURL}" |grep '<title>' |awk '{print $1}' |cut -c8-13)
        set -e
      fi
    done
    echo 'Please enter your Sonarr API key:'
    read -rs sonarrAPIKey
    echo ''
    echo 'Testing that the provided Sonarr API Key is valid...'
    echo ''
    sonarrAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${sonarrAPIKey}" |jq .[] |tr -d '"')
    while [ "${sonarrAPIKeyStatus}" = 'invalid' ]; do
      if [ "${sonarrAPITestResponse}" = 'Unauthorized' ]; then
        echo -e "${red}There was an error while attempting to validate the provided API key!${endColor}"
        echo 'Please enter your Sonarr API key:'
        read -rs sonarrAPIKey
        echo ''
        sonarrAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${sonarrAPIKey}" |jq .[] |tr -d '"')
      elif [ "${sonarrAPITestResponse}" != 'Unauthorized' ]; then
        sed -i.bak "${sonarrAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='ok'/" "${scriptname}"
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
    curl -s --location --request PUT "${userMBURL}configure/${endpoint}?" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "${mbClientID}" \
    -H "Authorization: Bearer ${plexServerMBToken}" \
    --data "url=${JSONConvertedURL}&apikey=${sonarrAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${sonarrConfigFile}"
    sonarrMBConfigTestResponse=$(cat "${sonarrConfigFile}" |jq .message |tr -d '"')
    if [ "${sonarrMBConfigTestResponse}" = 'success' ]; then
      echo -e "${grn}Success!${endColor}"
      echo ''
      echo 'Saving the Sonarr config to MediaButler...'
      curl -s --location --request POST "${userMBURL}configure/${endpoint}?" \
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
    endpoint='sonarr4k'
    if [[ "${sonarr4kURLStatus}" = 'ok' ]] && [[ "${sonarr4kAPIKeyStatus}" = 'ok' ]]; then
      sonarr4kSetupCheck=$(curl -s --location --request GET "${userMBURL}configure/${endpoint}?" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -H "${mbClientID}" \
      -H "Authorization: Bearer ${plexServerMBToken}" |jq .settings)
      if [ "${sonarr4kSetupCheck}" != '{}' ]; then
        echo -e "${red}Sonarr 4K appears to be setup already!${endColor}"
        echo -e "${ylw}Do you wish to continue?${endColor}"
        echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o:"
        read -r continuePrompt
        if ! [[ "${continuePrompt}" =~ ^(yes|y|Yes|Y|no|n|No|N)$ ]]; then
          echo -e "${red}Please specify yes, y, no, or n.${endColor}"
        elif [[ "${continuePrompt}" =~ ^(yes|y|Yes|Y)$ ]]; then
          sed -i.bak "${sonarr4kURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='invalid'/" "${scriptname}"
          sonarr4kURLStatus='invalid'
          sed -i.bak "${sonarr4kAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='invalid'/" "${scriptname}"
          sonarr4kAPIKeyStatus='invalid'
        elif [[ "${continuePrompt}" =~ ^(no|n|No|N)$ ]]; then
          sonarr_menu
        fi
      elif [ "${sonarr4kSetupCheck}" = '{}' ]; then
        :
      fi
    elif [[ "${sonarr4kURLStatus}" = 'invalid' ]] || [[ "${sonarr4kAPIKeyStatus}" = 'invalid' ]]; then
      :
    fi
    echo 'Please enter your Sonarr 4K URL (IE: http://127.0.0.1:8989/sonarr/):'
    read -r providedURL
    echo ''
    echo 'Checking that the provided Sonarr 4K URL is valid...'
    echo ''
    convert_url
    set +e
    sonarr4kURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
    sonarr4kURLAppCheckResponse=$(curl -s --connect-timeout 10 "${convertedURL}" |grep '<title>' |awk '{print $1}' |cut -c8-13)
    set -e
    while [ "${sonarr4kURLStatus}" = 'invalid' ]; do
      if [[ "${sonarr4kURLCheckResponse}" = '200' ]] && [[ "${sonarr4kURLAppCheckResponse}" = 'Sonarr' ]]; then
        sed -i.bak "${sonarr4kURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='ok'/" "${scriptname}"
        sonarr4kURLStatus='ok'
        echo -e "${grn}Success!${endColor}"
        echo ''
      elif [[ "${sonarr4kURLCheckResponse}" != '200' ]] || [[ "${sonarr4kURLAppCheckResponse}" != 'Sonarr' ]]; then
        echo -e "${red}There was an error while attempting to validate the provided URL!${endColor}"
        echo 'Please enter your Sonarr 4k URL (IE: http://127.0.0.1:8989/sonarr/):'
        read -r providedURL
        echo ''
        echo 'Checking that the provided Sonarr 4k URL is valid...'
        echo ''
        convert_url
        set +e
        sonarr4kURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
        sonarr4kURLAppCheckResponse=$(curl -s --connect-timeout 10 "${convertedURL}" |grep '<title>' |awk '{print $1}' |cut -c8-13)
        set -e
      fi
    done
    echo 'Please enter your Sonarr 4K API key:'
    read -rs sonarr4kAPIKey
    echo ''
    echo 'Testing that the provided Sonarr 4K API Key is valid...'
    echo ''
    sonarr4kAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${sonarr4kAPIKey}" |jq .[] |tr -d '"')
    while [ "${sonarr4kAPIKeyStatus}" = 'invalid' ]; do
      if [ "${sonarr4kAPITestResponse}" = 'Unauthorized' ]; then
        echo -e "${red}There was an error while attempting to validate the provided API key!${endColor}"
        echo 'Please enter your Sonarr 4K API key:'
        read -rs sonarr4kAPIKey
        echo ''
        sonarr4kAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${sonarr4kAPIKey}" |jq .[] |tr -d '"')
      elif [ "${sonarr4kAPITestResponse}" != 'Unauthorized' ]; then
        sed -i.bak "${sonarr4kAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='ok'/" "${scriptname}"
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
    curl -s --location --request PUT "${userMBURL}configure/${endpoint}?" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "${mbClientID}" \
    -H "Authorization: Bearer ${plexServerMBToken}" \
    --data "url=${JSONConvertedURL}&apikey=${sonarr4kAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${sonarr4kConfigFile}"
    sonarr4kMBConfigTestResponse=$(cat "${sonarr4kConfigFile}" |jq .message |tr -d '"')
    if [ "${sonarr4kMBConfigTestResponse}" = 'success' ]; then
      echo -e "${grn}Success!${endColor}"
      echo ''
      echo 'Saving the Sonarr 4K config to MediaButler...'
      curl -s --location --request POST "${userMBURL}configure/${endpoint}?" \
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
    endpoint='radarr'
    if [[ "${radarrURLStatus}" = 'ok' ]] && [[ "${radarrAPIKeyStatus}" = 'ok' ]]; then
      radarrSetupCheck=$(curl -s --location --request GET "${userMBURL}configure/${endpoint}?" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -H "${mbClientID}" \
      -H "Authorization: Bearer ${plexServerMBToken}" |jq .settings)
      if [ "${radarrSetupCheck}" != '{}' ]; then
        echo -e "${red}Radarr appears to be setup already!${endColor}"
        echo -e "${ylw}Do you wish to continue?${endColor}"
        echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o:"
        read -r continuePrompt
        if ! [[ "${continuePrompt}" =~ ^(yes|y|Yes|Y|no|n|No|N)$ ]]; then
          echo -e "${red}Please specify yes, y, no, or n.${endColor}"
        elif [[ "${continuePrompt}" =~ ^(yes|y|Yes|Y)$ ]]; then
          sed -i.bak "${radarrURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='invalid'/" "${scriptname}"
          radarrURLStatus='invalid'
          sed -i.bak "${radarrAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='invalid'/" "${scriptname}"
          radarrAPIKeyStatus='invalid'
        elif [[ "${continuePrompt}" =~ ^(no|n|No|N)$ ]]; then
          radarr_menu
        fi
      elif [ "${radarrSetupCheck}" = '{}' ]; then
        :
      fi
    elif [[ "${radarrURLStatus}" = 'invalid' ]] || [[ "${radarrAPIKeyStatus}" = 'invalid' ]]; then
      :
    fi
    echo 'Please enter your Radarr URL (IE: http://127.0.0.1:8989/radarr/):'
    read -r providedURL
    echo ''
    echo 'Checking that the provided Radarr URL is valid...'
    echo ''
    convert_url
    set +e
    radarrURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
    radarrURLAppCheckResponse=$(curl -s --connect-timeout 10 "${convertedURL}" |grep '<title>' |awk '{print $1}' |cut -c8-13)
    set -e
    while [ "${radarrURLStatus}" = 'invalid' ]; do
      if [[ "${radarrURLCheckResponse}" = '200' ]] && [[ "${radarrURLAppCheckResponse}" = 'Radarr' ]]; then
        sed -i.bak "${radarrURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='ok'/" "${scriptname}"
        radarrURLStatus='ok'
        echo -e "${grn}Success!${endColor}"
        echo ''
      elif [[ "${radarrURLCheckResponse}" != '200' ]] || [[ "${radarrURLAppCheckResponse}" != 'Radarr' ]]; then
        echo -e "${red}There was an error while attempting to validate the provided URL!${endColor}"
        echo 'Please enter your Radarr URL (IE: http://127.0.0.1:8989/radarr/):'
        read -r providedURL
        echo ''
        echo 'Checking that the provided Radarr URL is valid...'
        echo ''
        convert_url
        set +e
        radarrURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
        radarrURLAppCheckResponse=$(curl -s --connect-timeout 10 "${convertedURL}" |grep '<title>' |awk '{print $1}' |cut -c8-13)
        set -e
      fi
    done
    echo 'Please enter your Radarr API key:'
    read -rs radarrAPIKey
    echo ''
    echo 'Testing that the provided Radarr API Key is valid...'
    echo ''
    radarrAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${radarrAPIKey}" |jq .[] |tr -d '"')
    while [ "${radarrAPIKeyStatus}" = 'invalid' ]; do
      if [ "${radarrAPITestResponse}" = 'Unauthorized' ]; then
        echo -e "${red}There was an error while attempting to validate the provided API key!${endColor}"
        echo 'Please enter your Radarr API key:'
        read -rs radarrAPIKey
        echo ''
        radarrAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${radarrAPIKey}" |jq .[] |tr -d '"')
      elif [ "${radarrAPITestResponse}" != 'Unauthorized' ]; then
        sed -i.bak "${radarrAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='ok'/" "${scriptname}"
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
    curl -s --location --request PUT "${userMBURL}configure/${endpoint}?" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "${mbClientID}" \
    -H "Authorization: Bearer ${plexServerMBToken}" \
    --data "url=${JSONConvertedURL}&apikey=${radarrAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${radarrConfigFile}"
    radarrMBConfigTestResponse=$(cat "${radarrConfigFile}" |jq .message |tr -d '"')
    if [ "${radarrMBConfigTestResponse}" = 'success' ]; then
      echo -e "${grn}Success!${endColor}"
      echo ''
      echo 'Saving the Radarr config to MediaButler...'
      curl -s --location --request POST "${userMBURL}configure/${endpoint}?" \
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
    endpoint='radarr4k'
    if [[ "${radarr4kURLStatus}" = 'ok' ]] && [[ "${radarr4kAPIKeyStatus}" = 'ok' ]]; then
      radarr4kSetupCheck=$(curl -s --location --request GET "${userMBURL}configure/${endpoint}?" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -H "${mbClientID}" \
      -H "Authorization: Bearer ${plexServerMBToken}" |jq .settings)
      if [ "${radarr4kSetupCheck}" != '{}' ]; then
        echo -e "${red}Radarr 4K appears to be setup already!${endColor}"
        echo -e "${ylw}Do you wish to continue?${endColor}"
        echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o:"
        read -r continuePrompt
        if ! [[ "${continuePrompt}" =~ ^(yes|y|Yes|Y|no|n|No|N)$ ]]; then
          echo -e "${red}Please specify yes, y, no, or n.${endColor}"
        elif [[ "${continuePrompt}" =~ ^(yes|y|Yes|Y)$ ]]; then
          sed -i.bak "${radarr4kURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='invalid'/" "${scriptname}"
          radarr4kURLStatus='invalid'
          sed -i.bak "${radarr4kAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='invalid'/" "${scriptname}"
          radarr4kAPIKeyStatus='invalid'
        elif [[ "${continuePrompt}" =~ ^(no|n|No|N)$ ]]; then
          radarr4k_menu
        fi
      elif [ "${radarr4kSetupCheck}" = '{}' ]; then
        :
      fi
    elif [[ "${radarr4kURLStatus}" = 'invalid' ]] || [[ "${radarr4kAPIKeyStatus}" = 'invalid' ]]; then
      :
    fi
    echo 'Please enter your Radarr 4K URL (IE: http://127.0.0.1:8989/radarr/):'
    read -r providedURL
    echo ''
    echo 'Checking that the provided Radarr 4K URL is valid...'
    echo ''
    convert_url
    set +e
    radarr4kURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
    radarr4kURLAppCheckResponse=$(curl -s --connect-timeout 10 "${convertedURL}" |grep '<title>' |awk '{print $1}' |cut -c8-13)
    set -e
    while [ "${radarr4kURLStatus}" = 'invalid' ]; do
      if [[ "${radarr4kURLCheckResponse}" = '200' ]] && [[ "${radarr4kURLAppCheckResponse}" = 'Radarr' ]]; then
        sed -i.bak "${radarr4kURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='ok'/" "${scriptname}"
        radarr4kURLStatus='ok'
        echo -e "${grn}Success!${endColor}"
        echo ''
      elif [[ "${radarr4kURLCheckResponse}" != '200' ]] || [[ "${radarr4kURLAppCheckResponse}" != 'Radarr' ]]; then
        echo -e "${red}There was an error while attempting to validate the provided URL!${endColor}"
        echo 'Please enter your Radarr 4k URL (IE: http://127.0.0.1:8989/radarr/):'
        read -r providedURL
        echo ''
        echo 'Checking that the provided Radarr 4k URL is valid...'
        echo ''
        convert_url
        set +e
        radarr4kURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
        radarr4kURLAppCheckResponse=$(curl -s --connect-timeout 10 "${convertedURL}" |grep '<title>' |awk '{print $1}' |cut -c8-13)
        set -e
      fi
    done
    echo 'Please enter your Radarr 4K API key:'
    read -rs radarr4kAPIKey
    echo ''
    echo 'Testing that the provided Radarr 4K API Key is valid...'
    echo ''
    radarr4kAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${radarr4kAPIKey}" |jq .[] |tr -d '"')
    while [ "${radarr4kAPIKeyStatus}" = 'invalid' ]; do
      if [ "${radarr4kAPITestResponse}" = 'Unauthorized' ]; then
        echo -e "${red}There was an error while attempting to validate the provided API key!${endColor}"
        echo 'Please enter your Radarr 4K API key:'
        read -rs radarr4kAPIKey
        echo ''
        radarr4kAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${radarr4kAPIKey}" |jq .[] |tr -d '"')
      elif [ "${radarr4kAPITestResponse}" != 'Unauthorized' ]; then
        sed -i.bak "${radarr4kAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='ok'/" "${scriptname}"
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
    curl -s --location --request PUT "${userMBURL}configure/${endpoint}?" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "${mbClientID}" \
    -H "Authorization: Bearer ${plexServerMBToken}" \
    --data "url=${JSONConvertedURL}&apikey=${radarr4kAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${radarr4kConfigFile}"
    radarr4kMBConfigTestResponse=$(cat "${radarr4kConfigFile}" |jq .message |tr -d '"')
    if [ "${radarr4kMBConfigTestResponse}" = 'success' ]; then
      echo -e "${grn}Success!${endColor}"
      echo ''
      echo 'Saving the Radarr 4K config to MediaButler...'
      curl -s --location --request POST "${userMBURL}configure/${endpoint}?" \
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
    endpoint='radarr3d'
    if [[ "${radarr3dURLStatus}" = 'ok' ]] && [[ "${radarr3dAPIKeyStatus}" = 'ok' ]]; then
      radarr3dSetupCheck=$(curl -s --location --request GET "${userMBURL}configure/${endpoint}?" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -H "${mbClientID}" \
      -H "Authorization: Bearer ${plexServerMBToken}" |jq .settings)
      if [ "${radarr3dSetupCheck}" != '{}' ]; then
        echo -e "${red}Radarr 3D appears to be setup already!${endColor}"
        echo -e "${ylw}Do you wish to continue?${endColor}"
        echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o:"
        read -r continuePrompt
        if ! [[ "${continuePrompt}" =~ ^(yes|y|Yes|Y|no|n|No|N)$ ]]; then
          echo -e "${red}Please specify yes, y, no, or n.${endColor}"
        elif [[ "${continuePrompt}" =~ ^(yes|y|Yes|Y)$ ]]; then
          sed -i.bak "${radarr3dURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='invalid'/" "${scriptname}"
          radarr3dURLStatus='invalid'
          sed -i.bak "${radarr3dAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='invalid'/" "${scriptname}"
          radarr3dAPIKeyStatus='invalid'
        elif [[ "${continuePrompt}" =~ ^(no|n|No|N)$ ]]; then
          radarr3d_menu
        fi
      elif [ "${radarr3dSetupCheck}" = '{}' ]; then
        :
      fi
    elif [[ "${radarr3dURLStatus}" = 'invalid' ]] || [[ "${radarr3dAPIKeyStatus}" = 'invalid' ]]; then
      :
    fi
    echo 'Please enter your Radarr 3D URL (IE: http://127.0.0.1:8989/radarr/):'
    read -r providedURL
    echo ''
    echo 'Checking that the provided Radarr 3D URL is valid...'
    echo ''
    convert_url
    set +e
    radarr3dURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
    radarr3dURLAppCheckResponse=$(curl -s --connect-timeout 10 "${convertedURL}" |grep '<title>' |awk '{print $1}' |cut -c8-13)
    set -e
    while [ "${radarr3dURLStatus}" = 'invalid' ]; do
      if [[ "${radarr3dURLCheckResponse}" = '200' ]] && [[ "${radarr3dURLAppCheckResponse}" = 'Radarr' ]]; then
        sed -i.bak "${radarr3dURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='ok'/" "${scriptname}"
        radarr3dURLStatus='ok'
        echo -e "${grn}Success!${endColor}"
        echo ''
      elif [ "${radarr3dURLCheckResponse}" != '200' ]; then
        echo -e "${red}There was an error while attempting to validate the provided URL!${endColor}"
        echo 'Please enter your Radarr 4k URL (IE: http://127.0.0.1:8989/radarr/):'
        read -r providedURL
        echo ''
        echo 'Checking that the provided Radarr 4k URL is valid...'
        echo ''
        convert_url
        set +e
        radarr3dURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}")
        radarr3dURLAppCheckResponse=$(curl -s --connect-timeout 10 "${convertedURL}" |grep '<title>' |awk '{print $1}' |cut -c8-13)
        set -e
      fi
    done
    echo 'Please enter your Radarr 3D API key:'
    read -rs radarr3dAPIKey
    echo ''
    echo 'Testing that the provided Radarr 3D API Key is valid...'
    echo ''
    radarr3dAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${radarr3dAPIKey}" |jq .[] |tr -d '"')
    while [ "${radarr3dAPIKeyStatus}" = 'invalid' ]; do
      if [ "${radarr3dAPITestResponse}" = 'Unauthorized' ]; then
        echo -e "${red}There was an error while attempting to validate the provided API key!${endColor}"
        echo 'Please enter your Radarr 3D API key:'
        read -rs radarr3dAPIKey
        echo ''
        radarr3dAPITestResponse=$(curl -s -X GET "${convertedURL}api/system/status" -H "X-Api-Key: ${radarr3dAPIKey}" |jq .[] |tr -d '"')
      elif [ "${radarr3dAPITestResponse}" != 'Unauthorized' ]; then
        sed -i.bak "${radarr3dAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='ok'/" "${scriptname}"
        radarr3dAPIKeyStatus='ok'
        echo -e "${grn}Success!${endColor}"
      fi
    done
    curl -s -X GET "${convertedURL}api/profile" -H "X-Api-Key: ${radarr3dAPIKey}" |jq . > "${rawArrProfilesFile}"
    create_arr_profiles_list
    prompt_for_arr_profile
    curl -s -X GET "${convertedURL}api/rootfolder" -H "X-Api-Key: ${radarr3dAPIKey}" |jq . > "${rawArrRootDirsFile}"
    create_arr_root_dirs_list
    prompt_for_arr_root_dir
    echo 'Testing the full Radarr 3D config for MediaButler...'
    curl -s --location --request PUT "${userMBURL}configure/${endpoint}?" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "${mbClientID}" \
    -H "Authorization: Bearer ${plexServerMBToken}" \
    --data "url=${JSONConvertedURL}&apikey=${radarr3dAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${radarr3dConfigFile}"
    radarr3dMBConfigTestResponse=$(cat "${radarr3dConfigFile}" |jq .message |tr -d '"')
    if [ "${radarr3dMBConfigTestResponse}" = 'success' ]; then
      echo -e "${grn}Success!${endColor}"
      echo ''
      echo 'Saving the Radarr 3D config to MediaButler...'
      curl -s --location --request POST "${userMBURL}configure/${endpoint}?" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "${mbClientID}" \
      -H "Authorization: Bearer ${plexServerMBToken}" \
      --data "url=${JSONConvertedURL}&apikey=${radarr3dAPIKey}&defaultProfile=${selectedArrProfile}&defaultRoot=${selectedArrRootDir}" |jq . > "${radarrConfigFile}"
      radarr3dMBConfigPostResponse=$(cat "${radarr3dConfigFile}" |jq .message |tr -d '"')
      if [ "${radarr3dMBConfigPostResponse}" = 'success' ]; then
        echo -e "${grn}Done! Radarr 3D has been successfully configured for${endColor}"
        echo -e "${grn}MediaButler with the ${selectedPlexServerName} Plex server.${endColor}"
        sleep 3
        echo ''
        echo 'Returning you to the Main Menu...'
        main_menu
      elif [ "${radarr3dMBConfigPostResponse}" != 'success' ]; then
        echo -e "${red}Config push failed! Please try again later.${endColor}"
        sleep 3
        main_menu
      fi
    elif [ "${radarr3dMBConfigTestResponse}" != 'success' ]; then
      echo -e "${red}Hmm, something weird happened. Please try again.${endColor}"
      sleep 3
      main_menu
    fi
  fi
}

# Function to process Tautulli configuration
setup_tautulli() {
  endpoint='tautulli'
  if [[ "${tautulliURLStatus}" = 'ok' ]] && [[ "${tautulliAPIKeyStatus}" = 'ok' ]]; then
    tautulliSetupCheck=$(curl -s --location --request GET "${userMBURL}configure/${endpoint}?" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H "${mbClientID}" \
    -H "Authorization: Bearer ${plexServerMBToken}" |jq .settings)
    if [ "${tautulliSetupCheck}" != '{}' ]; then
      echo -e "${red}Tautulli appears to be setup already!${endColor}"
      echo -e "${ylw}Do you wish to continue?${endColor}"
      echo -e "${grn}[Y]${endColor}es or ${red}[N]${endColor}o:"
      read -r continuePrompt
      if ! [[ "${continuePrompt}" =~ ^(yes|y|Yes|Y|no|n|No|N)$ ]]; then
        echo -e "${red}Please specify yes, y, no, or n.${endColor}"
      elif [[ "${continuePrompt}" =~ ^(yes|y|Yes|Y)$ ]]; then
        sed -i.bak "${tautulliURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='invalid'/" "${scriptname}"
        tautulliURLStatus='invalid'
        sed -i.bak "${tautulliAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='invalid'/" "${scriptname}"
        tautulliAPIKeyStatus='invalid'
      elif [[ "${continuePrompt}" =~ ^(no|n|No|N)$ ]]; then
        main_menu
      fi
    elif [ "${tautulliSetupCheck}" = '{}' ]; then
      :
    fi
  elif [[ "${tautulliURLStatus}" = 'invalid' ]] || [[ "${tautulliAPIKeyStatus}" = 'invalid' ]]; then
    :
  fi
  echo 'Please enter your Tautulli URL (IE: http://127.0.0.1:8181/tautulli/):'
  read -r providedURL
  echo ''
  echo 'Checking that the provided Tautulli URL is valid...'
  echo ''
  convert_url
  set +e
  tautulliURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}"auth/login)
  tautulliURLAppCheckResponse=$(curl -s --connect-timeout 10 "${convertedURL}"auth/login?redirect_uri=/tautulli/ |grep '<title>' |awk '{print $1}' |cut -c8-)
  set -e
  while [ "${tautulliURLStatus}" = 'invalid' ]; do
    if [[ "${tautulliURLCheckResponse}" = '200' ]] && [[ "${tautulliURLAppCheckResponse}" = 'Tautulli' ]]; then
      sed -i.bak "${tautulliURLStatusLineNum} s/${endpoint}URLStatus='[^']*'/${endpoint}URLStatus='ok'/" "${scriptname}"
      tautulliURLStatus='ok'
      echo -e "${grn}Success!${endColor}"
      echo ''
    elif [[ "${tautulliURLCheckResponse}" != '200' ]] && [[ "${tautulliURLAppCheckResponse}" = 'Tautulli' ]]; then
      echo -e "${red}There was an error while attempting to validate the provided URL!${endColor}"
      echo 'Please enter your Tautulli URL (IE: http://127.0.0.1:8181/tautulli/):'
      read -r providedURL
      echo ''
      echo 'Checking that the provided Tautulli URL is valid...'
      echo ''
      convert_url
      set +e
      tautulliURLCheckResponse=$(curl --head --write-out "%{http_code}" -sI --output /dev/null --connect-timeout 10 "${convertedURL}"auth/login)
      tautulliURLAppCheckResponse=$(curl -s --connect-timeout 10 "${convertedURL}"auth/login?redirect_uri=/tautulli/ |grep '<title>' |awk '{print $1}' |cut -c8-)
      set -e
    fi
  done
  echo 'Please enter your Tautulli API key:'
  read -rs tautulliAPIKey
  echo ''
  echo 'Testing that the provided Tautulli API Key is valid...'
  echo ''
  tautulliAPITestResponse=$(curl -s "${convertedURL}api/v2?apikey=${tautulliAPIKey}&cmd=arnold" |jq .response.message |tr -d '"')
  while [ "${tautulliAPIKeyStatus}" = 'invalid' ]; do
    if [ "${tautulliAPITestResponse}" = 'null' ]; then
      sed -i.bak "${tautulliAPIKeyStatusLineNum} s/${endpoint}APIKeyStatus='[^']*'/${endpoint}APIKeyStatus='ok'/" "${scriptname}"
      tautulliAPIKeyStatus='ok'
      echo -e "${grn}Success!${endColor}"
      echo ''
    elif [ "${tautulliAPITestResponse}" = 'Invalid apikey' ]; then
      echo -e "${red}There was an error while attempting to validate the provided API key!${endColor}"
      echo 'Please enter your Tautulli API key:'
      read -rs tautulliAPIKey
      echo ''
      tautulliAPITestResponse=$(curl -s "${convertedURL}api/v2?apikey=${tautulliAPIKey}&cmd=arnold" |jq .response.message |tr -d '"')
    fi
  done
  echo 'Testing the full Tautulli config for MediaButler...'
  curl -s --location --request PUT "${userMBURL}configure/${endpoint}?" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "${mbClientID}" \
  -H "Authorization: Bearer ${plexServerMBToken}" \
  --data "url=${JSONConvertedURL}&apikey=${tautulliAPIKey}" |jq . > "${tautulliConfigFile}"
  tautulliMBConfigTestResponse=$(cat "${tautulliConfigFile}" |jq .message |tr -d '"')
  if [ "${tautulliMBConfigTestResponse}" = 'success' ]; then
    echo -e "${grn}Success!${endColor}"
    echo ''
    echo 'Saving the Tautulli config to MediaButler...'
    curl -s --location --request POST "${userMBURL}configure/${endpoint}?" \
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
  create_dir
  checks
  get_line_numbers
  #if [[ -e "${plexCredsFile}" ]]; then
  if [[ -e "${jsonEnvFile}" ]]; then
    sed -i.bak "${plexCredsStatusLineNum} s/plexCredsStatus='[^']*'/plexCredsStatus='ok'/" "${scriptname}"
    plexToken=$(jq '.data[] | select(.name=="plexToken")' "${jsonEnvFile}" |jq .value |tr -d '"')
    selectedPlexServerName=$(jq '.data[] | select(.name=="serverName")' "${jsonEnvFile}" |jq .value |tr -d '"')
    plexServerMBToken=$(jq '.data[] | select(.name=="mbToken")' "${jsonEnvFile}" |jq .value |tr -d '"')
    plexServerMachineID=$(jq '.data[] | select(.name=="machineId")' "${jsonEnvFile}" |jq .value |tr -d '"')
    userMBURL=$(jq '.data[] | select(.name=="mbURL")' "${jsonEnvFile}" |jq .value |tr -d '"')
  #elif [[ ! -f "${plexCredsFile}" ]]; then
  elif [[ ! -f "${jsonEnvFile}" ]]; then
    get_plex_creds
    check_plex_creds
  fi
  #if [[ -e "${plexTokenFile}" ]]; then
  if [[ -z "${plexToken}" ]]; then
    get_plex_token
  #elif [[ ! -f "${plexTokenFile}" ]]; then
  else
    :
  fi
  #if [[ -e "${plexServersFile}" ]]; then
  if [[ -z "${selectedPlexServerName}" ]] || [[ -z "${plexServerMachineID}" ]] || [[ -z "${userMBURL}" ]] || [[ -z "${plexServerMBToken}" ]]; then
    create_plex_servers_list
    prompt_for_plex_server
  #elif [[ ! -f "${plexServersFile}" ]]; then
  else
    :
  fi
  create_env_file
  #check_endpoints
  main_menu
}

main

