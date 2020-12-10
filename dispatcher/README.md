# Dispatcher

The dispatcher simplifies the communication between the horcruxes.
It should be deployed on a machine that is reachable by every participating horcrux.
The dispatcher transmits secret shares between horcruxes.
All the messages are encrypted with the RSA public key of the recipient, so there is no way for a dispatcher to access the secret data.

# Local setup

Run the following command from the home directory to start the dispatcher locally:
```shell script
DATABASE_PATH=sqlite:///./dispatcher.db uvicorn dispatcher.main:app --reload
```

# Remote access

You can deploy the dispatcher with any means on the public IP address. Alternatively, you can use [ngrok](https://ngrok.com/)
to allow other horcruxes to connect to your locally running dispatcher.

Run the following command in first terminal window:
```shell script
DATABASE_PATH=sqlite:///./dispatcher.db uvicorn dispatcher.main:app --reload
```

Run the following command in second terminal window:
```shell script
ngrok http 8000
```
