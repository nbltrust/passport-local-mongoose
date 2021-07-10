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
    const currentAttempts = user.get(options.attemptsField);

    if (currentAttempts > options.noIntervalAttempts) {
      const attemptsInterval = options.attemptsIntervalCalculator(currentAttempts);
      const calculatedInterval = attemptsInterval < options.maxInterval ? attemptsInterval : options.maxInterval;

      if (Date.now() - user.get(options.lastLoginField) < calculatedInterval) {
        options.attemptsTooSoonSideEffect(user, options);
        user.save(function (saveErr) {
          if (saveErr) {
            return cb(saveErr);
          }
          const newAttempts = user.get(options.attemptsField);
          const unlockAt = Math.floor(user.get(options.lastLoginField) + options.attemptsIntervalCalculator(newAttempts));
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
        user.set(options.attemptsField, user.get(options.attemptsField) + 1);
        user.save(function (saveErr) {
          if (saveErr) {
            return cb(saveErr);
          }
          const newAttempts = user.get(options.attemptsField);
          if (newAttempts >= options.maxAttempts) {
            return cb(null, false, new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError, newAttempts));
          } else {
            const restNoIntervalAttempts = options.noIntervalAttempts - newAttempts;
            if (restNoIntervalAttempts >= 0) {
              return cb(
                null,
                false,
                new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError, newAttempts, restNoIntervalAttempts)
              );
            } else {
              const unlockAt = Math.floor(user.get(options.lastLoginField) + options.attemptsIntervalCalculator(newAttempts));
              return cb(null, false, new errors.AttemptTooSoonError(options.errorMessages.AttemptTooSoonError, newAttempts, unlockAt));
            }
          }
        });
      } else {
        const currentAttempts = user.get(options.attemptsField);
        const restNoIntervalAttempts = Math.max(0, options.noIntervalAttempts - currentAttempts);
        return cb(
          null,
          false,
          new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError, currentAttempts, restNoIntervalAttempts)
        );
      }
    }
  });
}
