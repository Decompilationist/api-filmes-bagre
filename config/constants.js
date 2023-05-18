function define(name, value) {
    Object.defineProperty(exports, name, {
        value:      value,
        enumerable: true
    });
}

define("ADMIN_FEE", 0.15);
define("UTC_OFFSET", 7*3600*1000);
define("EXPIRATION_PERIOD", 365*24*3600*1000);
define("MEM_FEE", 20);