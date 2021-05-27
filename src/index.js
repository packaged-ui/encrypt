import {encryptFn as native, hasNative} from './impl/native.js'
import {encryptFn as poly} from './impl/poly.js'

export const encrypt = hasNative() ? native : poly;
