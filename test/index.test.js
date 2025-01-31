import findHTML from '../index.js';
import assert from 'assert';

describe('findHTML', function() {
    it('should match html script tags', function() {
        const testString = '<SCRIPT SRC=https://cdn.jsdelivr.net/gh/Moksh45/host-xss.rocks/index.js></SCRIPT>';
        assert.equal(findHTML(testString), true);
    })
});
