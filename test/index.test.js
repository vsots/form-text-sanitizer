import checkAndSanitizeString from '../index.js';
import assert from 'assert';

describe('Sanitize String', function() {
    /*
    *   Basic HTML Sanitizing
    */
    it('should match basic tags', function() {
        const testString = `This is a test input. <SCRIPT SRC=https://cdn.jsdelivr.net/host-xss.rocks/index.js></SCRIPT> Previous tags should not appear.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `This is a test input.  Previous tags should not appear.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   Basic Mustache Sanitizing
    */
    it('should match basic mustache expressions', function() {
        const testString = `This is a test input. {{XSS}} Mustache should not appear.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `This is a test input.  Mustache should not appear.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   Basic Combination HTML and Mustache Sanitizing
    */
    it('should match basic mustache expressions', function() {
        const testString = `This is a test input. <SCRIPT SRC=https://cdn.jsdelivr.net/host-xss.rocks/index.js></SCRIPT>{{XSS}} Mustache and HTML should not appear.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `This is a test input.  Mustache and HTML should not appear.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 2);
    })

    /*
    *   Malformed IMG Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#malformed-img-tags
    */
    it('should match malformed img tags', function() {
        const testString = `Begin Test<IMG """><SCRIPT>alert("XSS")</SCRIPT>"\>End Test`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin TestEnd Test`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   No Closing Script Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#no-closing-script-tags
    */
    it('should match non-closing script tags', function() {
        const testString = `Begin test <SCRIPT SRC=http://xss.rocks/xss.js?< B > End test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin test  End test.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   Half Open HTML/JavaScript XSS Vector
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#half-open-htmljavascript-xss-vector
    */
    it('should match half-open html', function() {
        const testString = `Begin test <IMG SRC="\`<javascript:alert>\`('XSS')" End Test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);
        
        const expectedString = `Begin test `;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   Multiple Angle Brackets with Encoding
    */
    it('should match multiple opening and closing angle brackets with different encodings', function() {
        const testString = `Begin test &lt;1234gjfk onload=alert('XSS')  Testing&#00062 <&#x0003csome things&#x3e some more&gt; End test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin test  End test.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   Multiple Curly Brackets with Encoding
    */
    it('should match multiple opening and closing curly brackets with different encodings', function() {
        const testString = `Begin test &lcub;%7b one &rcub}{{}}twothree&#0123;&#x007b&#x7d;&#000000125;&#x07b&#x007b} tester&#x007d;&rcub; End test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin test  End test.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   Multiple Double Quotes with Encoding
    */
    it('should match multiple double quotes with different encodings', function() {
        const testString = `Begin test <<&quot;"testing&#34;<&#0034> <testing %22> &#x22;>&#x0022 &#00000034;<&#x00000022;< End test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin test `;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 2);
    })

    /*
    *   Multiple Single Quotes with Encoding
    */
    it('should match multiple single quotes with different encodings', function() {
        const testString = `Begin test <<&apos;'testing&#39;<&#0039> <testing %27> &#x27;>&#x0027 &#00000039;<&#x00000027;< End test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin test `;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 2);
    })

    /*
    *   Multiple Backticks with Encoding
    */
    it('should match multiple backticks with different encodings', function() {
        const testString = `Begin test <<\`&DiacritICALGRAVE;testing&#96;<&#0096> <testing %60> &#x60;>&#x0060 &#00000096;>&DiacritICALGRAVE;< End test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin test `;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 2);
    })
});
