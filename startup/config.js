const config = require('config');

module.exports = function () {
    if (!config.get('jwtPrivateKey')) {
        throw new Error('FATAL ERROR: jwtPrivateKey is not defined.');
    }

    if (!config.get('jwtRefreshKey')) {
        throw new Error('FATAL ERROR: jwtRefreshKey is not defined.');
    }
}