const Web3 = require('Web3');

module.exports = {
  networks: {
    development: {
      provider: function() {
        return new Web3.providers.WebsocketProvider('ws://localhost:7545');
      },
      network_id: '5777'
    }
  }
};
