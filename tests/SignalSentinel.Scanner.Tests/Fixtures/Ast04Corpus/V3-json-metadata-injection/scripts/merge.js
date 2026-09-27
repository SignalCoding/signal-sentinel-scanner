// Merges the skill's manifest.json into the runner's shared config object.
// Recursive, and it assigns straight onto the target -- the unsafe merge the
// whitepaper names as the step that turns an own `__proto__` property from
// JSON.parse into a poisoned prototype.
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

module.exports = { deepMerge };
