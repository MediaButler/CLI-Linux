<p align="center"><img src="https://raw.githubusercontent.com/christronyxyocum/mb-setup-utility/assets/Images/mb_small.png"><img src="https://raw.githubusercontent.com/christronyxyocum/mb-setup-utility/assets/Images/bash_small.jpg"></p>

# MediaButler Linux CLI Utility

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/bf0b65fe02504b60a2439070c45dc3f8)](https://www.codacy.com/app/christronyxyocum/CLI-Linux?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=MediaButler/CLI-Linux&amp;utm_campaign=Badge_Grade)
[![Chat on Discord](https://img.shields.io/discord/379374148436230144.svg)](https://discord.gg/nH9t5sm)
[![made-with-bash](https://img.shields.io/badge/Made%20with-Bash-1f425f.svg)](https://www.gnu.org/software/bash/)
[![](https://badge-size.herokuapp.com/MediaButler/CLI-Linux/master/mb-linux-cli-utility.sh)](https://github.com/MediaButler/CLI-Linux/blob/master/mb-linux-cli-utility.sh)

## What is it?

A command line tool to enable usage of the [MediaButler Server](https://github.com/MediaButler/Server)

## Features

 - [x] Can configure Sonarr/Radarr/Tautulli for use with the [Server](https://github.com/MediaButler/Server)
 - [x] Add and Manage Requests
 - [ ] Add and Manage Issues
 - [x] Media Search
 - [x] Retrieve currently playing statistics
 - [x] Playback History

 ## Why do you need my Plex username and password?

 As the [Server](https://github.com/MediaButler/Server) only supports authenticated forms of communication we require this information to perform an authentication with Plex. This information is used ONLY to perform Plex authentication and is not saved. We do however save a resulting token that is unique that is saved so you do not have to perform authentication again.

 ## Requirements

 We have done everything in our power to limit the number of dependencies that this application requires and, for most Linux users, they should already be installed. However, in case you do not, you will need the following packages in order to run the utility:

  - bash
  - curl
  - jq
  - grep
  - sed

 ## Installing and Using

 The simplest method would be to either download the file manually or clone this git repository, marking the file as executable, and running it.

     git clone https://github.com/MediaButler/CLI-Linux.git
     cd CLI-Linux
     chmod +x mb-linux-cli-utility.sh
     ./mb-linux-cli-utility.sh

## Docker

You can also run the client inside a docker environment by running

    docker run -it mediabutler/cli-linux


## Support

Further help and support using this script can be found in [our Wiki](https://github.com/MediaButler/Wiki/wiki) or drop by our [Discord Server](https://discord.gg/nH9t5sm)

