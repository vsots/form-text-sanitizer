import findHTML from '../index.js';
import assert from 'assert';

describe('findHTML', function() {
    /*
    *   Basic XSS Test Without Filter Evasion
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#basic-xss-test-without-filter-evasion
    */
    it('should match html script tags', function() {
        const testString = `<SCRIPT SRC=https://cdn.jsdelivr.net/gh/Moksh45/host-xss.rocks/index.js></SCRIPT>`;
        const result = findHTML(testString);
        console.log("the result: ", result);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   XSS Locator (Polyglot)
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#xss-locator-polyglot
    */
    it('should match javascript, html attributes, and script tag', function() {
        const testString = `javascript:/*--></title></style></textarea></script></xmp>
        <svg/onload='+/"\`/+/onmouseover=1/+/[*/[]/+alert(42);//'>`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 3);
    })

    /*
    *   Malformed A Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#malformed-a-tags
    */
    it('should match a tags', function() {
        const testString = `\<a onmouseover="alert(document.cookie)"\>xxs link\</a\>`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })
});
