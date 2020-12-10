# Dispatcher

The dispatcher simplifies the communication between the horcruxes.
It should be deployed on a machine which is reachable by every participating horcrux.
The dispatcher transmits secret shares between horcruxes.
All the messages are encrypted with the RSA public key of the recipient, so there is no way for a dispatcher to access the secret data.

# Run locally

Run the following command from the home directory to start the dispatcher locally:
```shell script
DATABASE_PATH=sqlite:///./dispatcher.db uvicorn dispatcher.main:app --reload
```