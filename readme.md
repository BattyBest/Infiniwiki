# Infiniwiki

Infiniwiki is a dynamically generating AI-powered wikia system. The whole thing is designed from the ground-up with that purpose in mind.
Infiniwiki can generate a theoratically infinite amount of pages, and can run locally on your machine, or can use the cloud with OpenAI's api.
It offers to tools to regenerate pages or refine the page based on user feedback. The UI is entirely web-based and no-code, and allows for the user
to view the generation in progress.

MIT License. Do whatever you wish with this.
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Getting Started

To run the Flask application, [Gunicorn](https://gunicorn.org/) with [nginx](https://nginx.org/en/) is reccomended and tested to work.
A shell.nix, .envrc, and a simple run.sh are included in the repo for an instant easy setup on any NixOS system with direnv. The run.sh may also be used on other systems.

Before first startup, edit the code in 'templates' so that you can link a Terms of Service, contact information and Privacy Policy. These are needed to comply with regulations.

For first startup, do not allow outside connections, edit the included shell.nix or configure your system-wide config. Go to the website at localhost and set your admin password. This will make an user called "Admin" which you will need to use in order to manage your website.

Upon first startup, Infiniwiki will generate 3 files: a config file, a saved sites file and a SQL database. The config file stores options, the saved sites file stores the sites already generated, and the database stores users and user data for your wikia. The config file contains your secret key. Do not share either. The saved sites file is safe to share and doesn't contain personal info.

## Requirements

- [Flask](https://flask.palletsprojects.com/) - Web library
- [OpenAI](https://beta.openai.com/) - OpenAI-compatible API that serves models.
- AI Models, local or net. Non-instruct models are recommended.

# Tips

- HTTPS is not enabled by default. Edit the nginx config to enable it.
- If you are running the AI models locally, make sure the system prompt in your server is empty.
- This system is very easy to ddos simply by spamming prompts. Enable the rate-limiting in the config if your ever going to make it public.
- Similarly, remember to configure access levels, to prevent people from spamming the improve functionality.
- This system sources bootstrap from MaxCDN. CDN's are generally regarded as bad practice; download it and enable local-sourcing in the settings.
