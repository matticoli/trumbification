# Trumbification

 [![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC_BY--NC--SA_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)
 ![Discord Bot](https://img.shields.io/badge/Discord%20Bot-2b2d31?logo=Discord)
![Pycord](https://img.shields.io/badge/Pycord-2b2d31?logo=Python)
![Docker](https://img.shields.io/badge/Docker-2b2d31?logo=Docker)


<img alt="" src="https://media.discordapp.net/attachments/751863792219979776/1140027563054481488/bouncer-trumbus-bg-shoes.png" height="150" style="border-radius: 100"/>

A discord bot for user verification in university discords, designed for the [WPI IMGD](http://imgd.wpi.edu/) community discord. Named after [Trumbus](https://trumbus.wpi.edu), WPI IMGD's de-facto symbol/mascot entity/deity.

Though you are welcome to adapt it for your needs, the bot is not intended for use outside of the discord servers it was designed for and is provided as-is without guarantee of functionality or support.

## Features
- Create private thread and ping user on join
- UI-based role selection
- Code-based email verification
- Customizable channel/role assignments (persisted using `pickle`)

## Development
### Prerequisites:
- `python3.10` or later, installed with pip and python in your system PATH
- Windows: `env.bat` file in project root with the following variables set
    ```bash
    set MAIL_API_KEY= # API Key for SMTP2GO
    set MAIL_SENDER= # Sender email address for verification emails
    set MAIL_REPLYTO= # Reply-to email address for verification emails
    set BOT_TOKEN= # Discord bot token
    set HASH_SECRET= # Randomly generated secret for generating verification codes
    set BOTOWNER_ALERT_CHANNEL= # Channel ID to alert bot owner on critical errors
    set BOTOWNER_MENTION= # User or role ID to alert bot owner on critical errors
    set BOTOWNER_ALERT_ENABLED= # If set to truthy value, bot owner will be pinged when a critical error is logged
    ```
    For other environments, you can substitute this for a regular `.env` file

### Running for development
`watchfiles` is recommended to automatically restart the bot on code changes. Note that discord bot UI state is not persistent, so in-progress verification flows will be interrupted on restart 

Windows with Python11 (convenience script for my dev environment):
- ```
  .\dev.bat
  ```

Linux/MacOS/Other:
- ```
    source .env
    pip install -r requirements.txt
    pip install watchfiles
    python -m watchfiles "python main.py" .\trumbification\
    ```

## Deployment
A Dockerfile and sample compose file are included for docker-based deployments. These are not required for deployment. I like to use GitHub Actions to build a container image and use [Portainer](https://www.portainer.io/) on a personal server and deploy the application as a stack to facilitate updates and portability (this is a good budget CI/CD solution if you have a server to deploy on).

If you're not familiar with these technologies and are trying to adapt this for your own use, a cloud host like [Autocode](https://autocode.com/solutions/discord-bot-hosting/) might be worth looking into. Or you could just install Python or Docker Desktop on a spare computer and run it off of that. When in doubt, Google for secure ways to deploy Discord bots
> **Note:** All actions are logged by the bot by default. Do not deploy something like this carelessly, as it could result in bot users' personal data (emails and Discord usernames) being leaked.