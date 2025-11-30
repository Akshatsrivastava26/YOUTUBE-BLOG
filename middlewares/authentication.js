const { validateToken } = require("../services/authentication");

function checkForAuthenticationCookie(cookieName) {
    return (req, res, next) => {
        const tokenCookieValue = req.cookies[cookieName];
        
        if (!tokenCookieValue) {
            // No token → continue normally
            return next();
        }

        try {
            const userPayload = validateToken(tokenCookieValue);
            req.user = userPayload;
        } catch (error) {
            // Invalid token → still continue
        }

        return next();
    };
}

module.exports = {
    checkForAuthenticationCookie,
};
