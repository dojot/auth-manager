# mqtt-manager

## mqtt-manager

This container bundles mosquitto with mqtt-manager.
Mosquitto is an open source message broker that implements the MQTT protocol.
mqtt-manager provides a REST service to update mosquitto access control list (ACL)
and TLS options easily and 'on the fly'.

### Running
All mqtt-manager and mosquitto dependencies should be automatically downloaded and configured when building the container.

* mqtt-manager depends on a running instance of [ejbca-rest](http://github.com/dojot/ejbca-rest)

## API

The API documentation for mqtt-manager service is written as API blueprints.
To generate a simple web page from it, one may run the commands below.

```shell
npm install -g aglio # you may need sudo for this

# static webpage
aglio -i docs/mqtt-manager.apib -o docs/mqtt-manager.html

# serve apis locally
aglio -i docs/mqtt-manager.apib -s
```

