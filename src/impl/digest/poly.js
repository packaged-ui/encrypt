import md from "node-forge/lib/md.all";

/**
 * @param {string} data
 * @param {object} algorithm
 * @return {Promise<ArrayBuffer>}
 */
export function digestFn(data, algorithm = 'SHA-512')
{
  return new Promise(
    resolve =>
    {
      const mda = md.algorithms[algorithm.replace('-', '').toLowerCase()];
      const obj = mda.create();
      obj.update(data)
      resolve(obj.digest().toHex());
    });
}
