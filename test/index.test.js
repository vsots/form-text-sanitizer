import findHTML from '../index.js';
import assert from 'assert';

describe('Regex Matching', function() {
    /*
    *   Basic XSS Test Without Filter Evasion
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#basic-xss-test-without-filter-evasion
    */
    it('should match html script tags', function() {
        const testString = `<SCRIPT SRC=https://cdn.jsdelivr.net/gh/Moksh45/host-xss.rocks/index.js></SCRIPT>`;
        const result = findHTML(testString);
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
    })

    /*
    *   Malformed IMG Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#malformed-img-tags
    */
    it('should match img tags', function() {
        const testString = `<IMG """><SCRIPT>alert("XSS")</SCRIPT>"\>`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 4);
    })

    /*
    *   fromCharCode
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#fromcharcode
    */
    it('should match fromCharCode', function() {
        const testString = `fromCharCode(88,83,83))">Click Me!</a>`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Default SRC Tag to Get Past Filters that Check SRC Domain
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#default-src-tag-to-get-past-filters-that-check-src-domain
    */
    it('should match default src tag', function() {
        const testString = `SRC=# onmouseover="alert('xxs')">`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Default SRC Tag by Leaving it Empty
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#default-src-tag-by-leaving-it-empty
    */
    it('should match when src tag is empty', function() {
        const testString = `img SRC= onmouseover="alert('xxs')">`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Default SRC Tag by Leaving it out Entirely
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#default-src-tag-by-leaving-it-out-entirely
    */
    it('should match when src tag is left out entirely', function() {
        const testString = `img onmouseover="alert('xxs')">`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   On Error Alert
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#on-error-alert
    */
    it('should match with onerror tags', function() {
        const testString = `img SRC=/ onerror="alert(String.fromCharCode(88,83,83))"`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   IMG onerror and JavaScript Alert Encode
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#img-onerror-and-javascript-alert-encode
    */
    it('should match with onerror with encoding', function() {
        const testString = `img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Decimal HTML Character References
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#decimal-html-character-references
    */
    it('should match with href with decimal html characters', function() {
        const testString = `a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">Click Me</a>`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Decimal HTML Character References Without Trailing Semicolons
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#decimal-html-character-references-without-trailing-semicolons
    */
    it('should match with decimal html character references without trailing semicolons', function() {
        const testString = `a href="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">Click Me</a>`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Hexadecimal HTML Character References Without Trailing Semicolons
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#hexadecimal-html-character-references-without-trailing-semicolons
    */
    it('should match with hexadecimal html character references without trailing semicolons', function() {
        const testString = `a href="&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29">Click Me</a>`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Embedded Tab
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#embedded-tab
    */
    it('should match with encoded tab', function() {
        const testString = `a href="jav   ascript:alert('XSS');">Click Me</a>`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Embedded Encoded Tab
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#embedded-encoded-tab
    */
    it('should match with embedded encoded tab', function() {
        const testString = `a href="jav&#x09;ascript:alert('XSS');">Click Me</a>`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Embedded Newline to Break Up XSS
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#embedded-newline-to-break-up-xss
    */
    it('should match with newline', function() {
        const testString1 = `a href="jav&#x0A;ascript:alert('XSS');">Click Me</a>`;
        const result1 = findHTML(testString1);

        const testString2 = `perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out`;
        const result2 = findHTML(testString2);
        
        const testString3 = `a href=" &#14;  javascript:alert('XSS');">Click Me</a>`;
        const result3 = findHTML(testString3);

        const testString4 = `SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>`;
        const result4 = findHTML(testString4);
        
        const testString5 = `BODY onload!#$%&()*~+-_.,:;?@[/|\]^\`=alert("XSS")>`;
        const result5 = findHTML(testString5);

        const testString6 = `SCRIPT/SRC="http://xss.rocks/xss.js"></SCRIPT>`;
        const result6 = findHTML(testString6);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 1);

        assert.equal(result3[0], true);
        assert.equal(result3[1].length, 2);

        assert.equal(result4[0], true);
        assert.equal(result4[1].length, 2);

        assert.equal(result5[0], true);
        assert.equal(result5[1].length, 1);

        assert.equal(result6[0], true);
        assert.equal(result6[1].length, 2);
    })

    /*
    *   Extraneous Open Brackets
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#extraneous-open-brackets
    */
    it('should match tags with extraneous open brackets', function() {
        const testString = `<<SCRIPT>alert("XSS");//\<</SCRIPT>`;
        const result = findHTML(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 3);
    })    
});
