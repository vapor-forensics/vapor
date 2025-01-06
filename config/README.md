# Deployment with Kamal

This folder contains the configuration and scripts for deploying using [Kamal](https://kamal-deploy.org/),
a Ruby-based deployment tool.

The full documentation can be found at [docs.saaspegasus.com/deployment/kamal/](https://docs.saaspegasus.com/deployment/kamal/).

Below are some useful commands for deploying and managing the app.

See the [Kamal documentation](https://kamal-deploy.org/docs/commands) for more commands.

## Updating Django Settings

If you need to make changes to the Django environment variables, you can do so by editing the `.kamal/secrets`
file and then doing a deploy (`kamal deploy`) to push the changes to the servers.
Each deploy will make the latest secrets available on all containers as environment variables.

## Deploy

Deploys can be done by running:

```
kamal deploy
```

This will deploy the latest local copy of your application code.

## Accessing logs

You can view the logs using Kamal by running:

```bash
kamal app logs
```

See `kamal app logs --help` for more details.

You can also access them directly on your server using `docker logs`.
