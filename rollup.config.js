import {terser} from 'rollup-plugin-terser';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

process.chdir(__dirname);

const testCfg = {
  input: './test/test.js',
  output: {
    file: './build/test.min.js',
    format: 'iife',
  },
  onwarn: function (warning)
  {
    // Skip certain warnings

    // should intercept ... but doesn't in some rollup versions
    if(warning.code === 'THIS_IS_UNDEFINED')
    {
      return;
    }

    // console.warn everything else
    console.warn(warning.message);
  },
  plugins: [
    resolve({browser: true, preferBuiltins: false}),
    commonjs(),
    terser(),
  ]
};

export default [testCfg];
