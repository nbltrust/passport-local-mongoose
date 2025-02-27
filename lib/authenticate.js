const scmp = require('scmp');

const pbkdf2 = require('./pbkdf2');
const errors = require('./errors');

// authenticate function needs refactoring - to avoid bugs we wrapped a bit dirty
module.exports = function (user, password, options, cb) {
  if (cb) {
    return authenticate(user, password, options, cb);
  }

  return new Promise((resolve, reject) => {
    authenticate(user, password, options, (err, user, error) => (err ? reject(err) : resolve({ user, error })));
  });
};

function authenticate(user, password, options, cb) {
  if (options.limitAttempts) {
    const currentAttempts = user.get(options.attemptsField) || 0;

    if (currentAttempts > options.noIntervalAttempts) {
      const attemptsInterval = options.attemptsIntervalCalculator(currentAttempts);
      const calculatedInterval = attemptsInterval < options.maxInterval ? attemptsInterval : options.maxInterval;
      const lastLoginAt = new Date(user.get(options.lastLoginField)).valueOf();
      if (Date.now() - lastLoginAt < calculatedInterval) {
        options.attemptsTooSoonSideEffect(user, options);
        user.save(function (saveErr) {
          if (saveErr) {
            return cb(saveErr);
          }
          const newAttempts = user.get(options.attemptsField) || 0;
          const currentLoginAt = new Date(user.get(options.lastLoginField)).valueOf();
          const nextInterval = options.attemptsIntervalCalculator(newAttempts);
          const calculatedInterval = nextInterval < options.maxInterval ? nextInterval : options.maxInterval;
          const unlockAt = Math.floor(currentLoginAt + calculatedInterval);
          return cb(null, false, new errors.AttemptTooSoonError(options.errorMessages.AttemptTooSoonError, newAttempts, unlockAt));
        });
        return;
      }
    } // these attempts no interval

    if (currentAttempts >= options.maxAttempts) {
      return cb(null, false, new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError));
    }
  }

  if (!user.get(options.saltField)) {
    return cb(null, false, new errors.NoSaltValueStoredError(options.errorMessages.NoSaltValueStoredError));
  }

  pbkdf2(password, user.get(options.saltField), options, function (err, hashBuffer) {
    if (err) {
      return cb(err);
    }

    if (scmp(hashBuffer, Buffer.from(user.get(options.hashField), options.encoding))) {
      if (options.limitAttempts) {
        user.set(options.lastLoginField, Date.now());
        user.set(options.attemptsField, 0);
        user.save(function (saveErr, user) {
          if (saveErr) {
            return cb(saveErr);
          }
          return cb(null, user);
        });
      } else {
        return cb(null, user);
      }
    } else {
      if (options.limitAttempts) {
        user.set(options.lastLoginField, Date.now());
        const currentAttempts = user.get(options.attemptsField) || 0;
        if (currentAttempts > options.noIntervalAttempts) {
          user.set(options.attemptsField, 1);
        } else {
          user.set(options.attemptsField, currentAttempts + 1);
        }
        user.save(function (saveErr) {
          if (saveErr) {
            return cb(saveErr);
          }
          const newAttempts = user.get(options.attemptsField) || 0;
          if (newAttempts >= options.maxAttempts) {
            return cb(null, false, new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError, newAttempts));
          } else {
            const restNoIntervalAttempts = options.noIntervalAttempts - newAttempts;
            if (restNoIntervalAttempts >= 0) {
              return cb(
                null,
                false,
                new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError, newAttempts, restNoIntervalAttempts + 1)
              );
            } else {
              const currentLoginAt = new Date(user.get(options.lastLoginField)).valueOf();
              const nextInterval = options.attemptsIntervalCalculator(newAttempts);
              const calculatedInterval = nextInterval < options.maxInterval ? nextInterval : options.maxInterval;
              const unlockAt = Math.floor(currentLoginAt + calculatedInterval);
              return cb(null, false, new errors.AttemptTooSoonError(options.errorMessages.AttemptTooSoonError, newAttempts, unlockAt));
            }
          }
        });
      } else {
        const currentAttempts = user.get(options.attemptsField) || 0;
        const restNoIntervalAttempts = Math.max(0, options.noIntervalAttempts - currentAttempts);
        return cb(
          null,
          false,
          new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError, currentAttempts, restNoIntervalAttempts + 1)
        );
      }
    }
  });
}
