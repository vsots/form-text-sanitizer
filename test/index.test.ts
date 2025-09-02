import sanitizeAndValidate from './../index.js';
import { promises as dns } from 'node:dns';
import assert from 'assert';
import sinon from 'sinon';

describe('String Matcher and Sanitizer', function() {
    /*
    *   Basic HTML Sanitizing
    */
    it('should match basic html', function() {
        const testString = `This is a test input. <SCRIPT SRC=https://cdn.jsdelivr.net/host-xss.rocks/index.js></SCRIPT> Previous tags should not appear.`;
        const { originalString, suggestedString, matches } = sanitizeAndValidate.checkAndSanitizeString(testString);

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
        const { originalString, suggestedString, matches } = sanitizeAndValidate.checkAndSanitizeString(testString);

        const expectedString = `This is a test input.  Mustache should not appear.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   Basic Combination HTML and Mustache Sanitizing
    */
    it('should match basic html and mustache expressions together', function() {
        const testString = `This is a test input. <SCRIPT SRC=https://cdn.jsdelivr.net/host-xss.rocks/index.js></SCRIPT>{{XSS}} Mustache and HTML should not appear.`;
        const { originalString, suggestedString, matches } = sanitizeAndValidate.checkAndSanitizeString(testString);

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
        const { originalString, suggestedString, matches } = sanitizeAndValidate.checkAndSanitizeString(testString);

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
        const { originalString, suggestedString, matches } = sanitizeAndValidate.checkAndSanitizeString(testString);

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
        const { originalString, suggestedString, matches } = sanitizeAndValidate.checkAndSanitizeString(testString);
        
        const expectedString = `Begin test `;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   XSS Using HTML Quote Encapsulation
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#xss-using-html-quote-encapsulation
    */
    it('should match XSS Using HTML Quote Encapsulation', function() {
        const testString1 = `<SCRIPT a="><" SRC="httx://xss.rocks/xss.js"`;
        const testString2 = `<SCRIPT ="><" SRC="httx://xss.rocks/xss.js"`;
        const testString3 = `<SCRIPT a="><" '' SRC="httx://xss.rocks/xss.js"`;
        const testString4 = `<SCRIPT "a='><'" SRC="httx://xss.rocks/xss.js"`;
        const testString5 = `<SCRIPT a=\`><\` SRC="httx://xss.rocks/xss.js"`;
        const testString6 = `<SCRIPT a="><'><" SRC="httx://xss.rocks/xss.js"`;
        const testString7 = `<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="httx://xss.rocks/xss.js"></SCRIPT>`;

        const expectedString = '';

        const result1 = sanitizeAndValidate.checkAndSanitizeString(testString1);
        const result2 = sanitizeAndValidate.checkAndSanitizeString(testString2);
        const result3 = sanitizeAndValidate.checkAndSanitizeString(testString3);
        const result4 = sanitizeAndValidate.checkAndSanitizeString(testString4);
        const result5 = sanitizeAndValidate.checkAndSanitizeString(testString5);
        const result6 = sanitizeAndValidate.checkAndSanitizeString(testString6);
        const result7 = sanitizeAndValidate.checkAndSanitizeString(testString7);

        assert.equal(result1.originalString, testString1);
        assert.equal(result1.suggestedString, expectedString);
        assert.equal(result1.matches.length, 1);

        assert.equal(result2.originalString, testString2);
        assert.equal(result2.suggestedString, expectedString);
        assert.equal(result2.matches.length, 1);

        assert.equal(result3.originalString, testString3);
        assert.equal(result3.suggestedString, expectedString);
        assert.equal(result3.matches.length, 1);

        assert.equal(result4.originalString, testString4);
        assert.equal(result4.suggestedString, expectedString);
        assert.equal(result4.matches.length, 1);

        assert.equal(result5.originalString, testString5);
        assert.equal(result5.suggestedString, expectedString);
        assert.equal(result5.matches.length, 1);

        assert.equal(result6.originalString, testString6);
        assert.equal(result6.suggestedString, expectedString);
        assert.equal(result6.matches.length, 1);

        assert.equal(result7.originalString, testString7);
        assert.equal(result7.suggestedString, expectedString);
        assert.equal(result7.matches.length, 1);
    })

    /*
    *   Multiple Angle Brackets with Encoding
    */
    it('should match multiple opening and closing angle brackets with different encodings', function() {
        const testString = `Begin test &lt;1234gjfk onload=alert('XSS')  Testing&#00062 <&#x0003csome things&#x3e some more&gt; End test.`;
        const { originalString, suggestedString, matches } = sanitizeAndValidate.checkAndSanitizeString(testString);

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
        const { originalString, suggestedString, matches } = sanitizeAndValidate.checkAndSanitizeString(testString);

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
        const { originalString, suggestedString, matches } = sanitizeAndValidate.checkAndSanitizeString(testString);

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
        const { originalString, suggestedString, matches } = sanitizeAndValidate.checkAndSanitizeString(testString);

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
        const { originalString, suggestedString, matches } = sanitizeAndValidate.checkAndSanitizeString(testString);

        const expectedString = `Begin test `;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 2);
    })

    /*
    *   WAF ByPass Strings for XSS
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#waf-bypass-strings-for-xss
    */
    it('should match WAF ByPass Strings for XSS', function() {
        const testString1 = `<Img src = x onerror = "javascript: window.onerror = alert; throw XSS">`;
        const testString2 = `<Video> <source onerror = "javascript: alert (XSS)">`;
        const testString3 = `<Input value = "XSS" type = text>`;
        const testString4 = `<applet code="javascript:confirm(document.cookie);">`;   
        const testString5 = `<isindex x="javascript:" onmouseover="alert(XSS)">`;
        const testString6 = `"></SCRIPT>”>’><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>`;
        const testString7 = `"><img src="x:x" onerror="alert(XSS)">`;
        const testString8 = `"><iframe src="javascript:alert(XSS)">`;
        const testString9 = `<object data="javascript:alert(XSS)">`;
        const testString10 = `<isindex type=image src=1 onerror=alert(XSS)>`;
        const testString11 = `<img src=x:alert(alt) onerror=eval(src) alt=0>`;
        const testString12 = `<img src="x:gif" onerror="window['al\u0065rt'](0)"></img>`;
        const testString13 = `<iframe/src="data:text/html,<svg onload=alert(1)>">`;
        const testString14 = `<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>`;
        const testString15 = `<svg><script xlink:href=data&colon;,window.open('https://www.google.com/')></script`;
        const testString16 = `<meta http-equiv="refresh" content="0;url=javascript:confirm(1)">`;
        const testString17 = `<iframe src=javascript&colon;alert&lpar;document&period;location&rpar;>`;
        const testString18 = `<form><a href="javascript:\u0061lert(1)">X`;
        const testString19 = `</script><img/*%00/src="worksinchrome&colon;prompt(1)"/%00*/onerror='eval(src)'>`;
        const testString20 = `<style>//*{x:expression(alert(/xss/))}//<style></style>`;
        const testString21 = `<img src="/" =_=" title="onerror='prompt(1)'">`;
        const testString22 = `<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script:&#97lert(1)>ClickMe`;
        const testString23 = `<script x> alert(1) </script 1=2`;
        const testString24 = `<form><button formaction=javascript&colon;alert(1)>CLICKME`;
        const testString25 = `<input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"`;
        const testString26 = `<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>`;
        const testString27 = `<OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"><PARAM NAME="DataURL" VALUE="javascript:alert(1)"></OBJECT>`;
        
        const expectedString1 = '';
        const expectedString2 = '">';
        const expectedString3 = 'X';
        const expectedString4 = "ClickMe";
        const expectedString5 = "CLICKME";

        const result1 = sanitizeAndValidate.checkAndSanitizeString(testString1);
        const result2 = sanitizeAndValidate.checkAndSanitizeString(testString2);
        const result3 = sanitizeAndValidate.checkAndSanitizeString(testString3);
        const result4 = sanitizeAndValidate.checkAndSanitizeString(testString4);
        const result5 = sanitizeAndValidate.checkAndSanitizeString(testString5);
        const result6 = sanitizeAndValidate.checkAndSanitizeString(testString6);
        const result7 = sanitizeAndValidate.checkAndSanitizeString(testString7);
        const result8 = sanitizeAndValidate.checkAndSanitizeString(testString8);
        const result9 = sanitizeAndValidate.checkAndSanitizeString(testString9);
        const result10 = sanitizeAndValidate.checkAndSanitizeString(testString10);
        const result11 = sanitizeAndValidate.checkAndSanitizeString(testString11);
        const result12 = sanitizeAndValidate.checkAndSanitizeString(testString12);
        const result13 = sanitizeAndValidate.checkAndSanitizeString(testString13);
        const result14 = sanitizeAndValidate.checkAndSanitizeString(testString14);
        const result15 = sanitizeAndValidate.checkAndSanitizeString(testString15);
        const result16 = sanitizeAndValidate.checkAndSanitizeString(testString16);
        const result17 = sanitizeAndValidate.checkAndSanitizeString(testString17);
        const result18 = sanitizeAndValidate.checkAndSanitizeString(testString18);
        const result19 = sanitizeAndValidate.checkAndSanitizeString(testString19);
        const result20 = sanitizeAndValidate.checkAndSanitizeString(testString20);
        const result21 = sanitizeAndValidate.checkAndSanitizeString(testString21);
        const result22 = sanitizeAndValidate.checkAndSanitizeString(testString22);
        const result23 = sanitizeAndValidate.checkAndSanitizeString(testString23);
        const result24 = sanitizeAndValidate.checkAndSanitizeString(testString24);
        const result25 = sanitizeAndValidate.checkAndSanitizeString(testString25);
        const result26 = sanitizeAndValidate.checkAndSanitizeString(testString26);
        const result27 = sanitizeAndValidate.checkAndSanitizeString(testString27);

        assert.equal(result1.originalString, testString1);
        assert.equal(result1.suggestedString, expectedString1);
        assert.equal(result1.matches.length, 1);

        assert.equal(result2.originalString, testString2);
        assert.equal(result2.suggestedString, expectedString1);
        assert.equal(result2.matches.length, 1);

        assert.equal(result3.originalString, testString3);
        assert.equal(result3.suggestedString, expectedString1);
        assert.equal(result3.matches.length, 1);

        assert.equal(result4.originalString, testString4);
        assert.equal(result4.suggestedString, expectedString1);
        assert.equal(result4.matches.length, 1);

        assert.equal(result5.originalString, testString5);
        assert.equal(result5.suggestedString, expectedString1);
        assert.equal(result5.matches.length, 1);

        assert.equal(result6.originalString, testString6);
        assert.equal(result6.suggestedString, expectedString2);
        assert.equal(result6.matches.length, 1);

        assert.equal(result7.originalString, testString7);
        assert.equal(result7.suggestedString, expectedString2);
        assert.equal(result7.matches.length, 1);

        assert.equal(result8.originalString, testString8);
        assert.equal(result8.suggestedString, expectedString2);
        assert.equal(result8.matches.length, 1);

        assert.equal(result9.originalString, testString9);
        assert.equal(result9.suggestedString, expectedString1);
        assert.equal(result9.matches.length, 1);

        assert.equal(result10.originalString, testString10);
        assert.equal(result10.suggestedString, expectedString1);
        assert.equal(result10.matches.length, 1);

        assert.equal(result11.originalString, testString11);
        assert.equal(result11.suggestedString, expectedString1);
        assert.equal(result11.matches.length, 1);

        assert.equal(result12.originalString, testString12);
        assert.equal(result12.suggestedString, expectedString1);
        assert.equal(result12.matches.length, 1);

        assert.equal(result13.originalString, testString13);
        assert.equal(result13.suggestedString, expectedString1);
        assert.equal(result13.matches.length, 1);

        assert.equal(result14.originalString, testString14);
        assert.equal(result14.suggestedString, expectedString1);
        assert.equal(result14.matches.length, 1);

        assert.equal(result15.originalString, testString15);
        assert.equal(result15.suggestedString, expectedString1);
        assert.equal(result15.matches.length, 2);

        assert.equal(result16.originalString, testString16);
        assert.equal(result16.suggestedString, expectedString1);
        assert.equal(result16.matches.length, 1);

        assert.equal(result17.originalString, testString17);
        assert.equal(result17.suggestedString, expectedString1);
        assert.equal(result17.matches.length, 1);

        assert.equal(result18.originalString, testString18);
        assert.equal(result18.suggestedString, expectedString3);
        assert.equal(result18.matches.length, 1);

        assert.equal(result19.originalString, testString19);
        assert.equal(result19.suggestedString, expectedString1);
        assert.equal(result19.matches.length, 1);

        assert.equal(result20.originalString, testString20);
        assert.equal(result20.suggestedString, expectedString1);
        assert.equal(result20.matches.length, 1);

        assert.equal(result21.originalString, testString21);
        assert.equal(result21.suggestedString, expectedString1);
        assert.equal(result21.matches.length, 1);

        assert.equal(result22.originalString, testString22);
        assert.equal(result22.suggestedString, expectedString4);
        assert.equal(result22.matches.length, 1);

        assert.equal(result23.originalString, testString23);
        assert.equal(result23.suggestedString, expectedString1);
        assert.equal(result23.matches.length, 2);

        assert.equal(result24.originalString, testString24);
        assert.equal(result24.suggestedString, expectedString5);
        assert.equal(result24.matches.length, 1);

        assert.equal(result25.originalString, testString25);
        assert.equal(result25.suggestedString, expectedString1);
        assert.equal(result25.matches.length, 1);

        assert.equal(result26.originalString, testString26);
        assert.equal(result26.suggestedString, expectedString1);
        assert.equal(result26.matches.length, 1);

        assert.equal(result27.originalString, testString27);
        assert.equal(result27.suggestedString, expectedString1);
        assert.equal(result27.matches.length, 1);
    })
});

describe('Email Address Domain Validation', function() {
    let spy = sinon.spy(dns, "resolveMx");

    afterEach(() => {
        spy.resetHistory();
    })

    it('should pass for a valid domain', async function() {
        const test = await sanitizeAndValidate.isValidDomain('gmail.com');
        sinon.assert.calledOnce(spy);
        assert.equal(test, true);
    })

    it('should fail for a domain with Null MX Record', async function() {
        const test = await sanitizeAndValidate.isValidDomain('example.com');
        sinon.assert.calledOnce(spy);
        assert.equal(test, false);
    })

    it('should fail for a domain with no data or not found by dns.resolveMx', async function() {
        const test = await sanitizeAndValidate.isValidDomain('fail.fail');
        sinon.assert.calledOnce(spy);
        assert.equal(test, false);
    })

    it('should fail regex check when hyphen is first character of subdomain', async function() {
        await sanitizeAndValidate.isValidDomain('-fail.com');
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when hyphen is last character of subdomain', async function() {
        await sanitizeAndValidate.isValidDomain('fail-.com');
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when hyphen is first character of TLD', async function() {
        await sanitizeAndValidate.isValidDomain('fail.-com');
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when hyphen is last character of TLD', async function() {
        await sanitizeAndValidate.isValidDomain('fail.com-');
        sinon.assert.notCalled(spy);
    })

    it('should pass regex when sub-domain is valid one character', async function() {
        await sanitizeAndValidate.isValidDomain('a.com');
        sinon.assert.calledOnce(spy);
    })

    it('should fail regex check when hyphen is one character sub-domain', async function() {
        await sanitizeAndValidate.isValidDomain('-.com');
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when hyphen is first character of two-character sub-domain', async function() {
        await sanitizeAndValidate.isValidDomain('-z.com');
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when hyphen is last character of two-character sub-domain', async function() {
        await sanitizeAndValidate.isValidDomain('z-.com');
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when hyphen is first character of three-character sub-domain', async function() {
        await sanitizeAndValidate.isValidDomain('-zb.com');
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when hyphen is last character of three-character sub-domain', async function() {
        await sanitizeAndValidate.isValidDomain('zb-.com');
        sinon.assert.notCalled(spy);
    })

    it('should pass regex check with multiple valid subdomains', async function() {
        await sanitizeAndValidate.isValidDomain('ab.bc.cd.com');
        sinon.assert.calledOnce(spy);
    })

    it('should fail regex check when invalid hyphen contained with multiple subdomains', async function() {
        await sanitizeAndValidate.isValidDomain('ab.b-.cd.com');
        sinon.assert.notCalled(spy);
    })

    it('should pass regex check when valid hyphen contained in subdomain', async function() {
        await sanitizeAndValidate.isValidDomain('a-b.com');
        sinon.assert.calledOnce(spy);
    })

    it('should pass regex check when valid hyphen contained in multiple subdomains', async function() {
        await sanitizeAndValidate.isValidDomain('ab.b-c.cd.com');
        sinon.assert.calledOnce(spy);
    })

    it('should fail regex check when no subdomain provided', async function() {
        await sanitizeAndValidate.isValidDomain('.com');
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when TLD is less than two characters', async function() {
        await sanitizeAndValidate.isValidDomain('abc.c');
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when TLD is all numeric', async function() {
        await sanitizeAndValidate.isValidDomain('abc.90876');
        sinon.assert.notCalled(spy);
    })

    it('should pass regex check when valid hyphen contained in TLD', async function() {
        await sanitizeAndValidate.isValidDomain('abc.ab-cd');
        sinon.assert.calledOnce(spy);
    })

    it('should fail regex check when no period character present', async function() {
        await sanitizeAndValidate.isValidDomain('abccom');
        sinon.assert.notCalled(spy);
    })

    it('should fail regex when consecutive period characters present', async function() {
        await sanitizeAndValidate.isValidDomain('abc..com');
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when domain is less than four characters', async function() {
        await sanitizeAndValidate.isValidDomain('a.b');
        sinon.assert.notCalled(spy);
    })

    it('should fail max character condition when domain is more than 255 characters', async function() {
        await sanitizeAndValidate.isValidDomain(`
            moarsubdomainmoarubdomainmoars.moarmoarsubdominmoaarsanmoarsubdomainmrsubdomain.moarsubdomainmoarmoarsubdomainmoarsubdomaimoarsubdomain.moarsubdooarmoarsubdomainmoarsubdomainmoarmoarsubdomain.moarsubdomainmoarmoarsubdomainmoarsubdomainmoarmoarsubdomain.com
        `);
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when subdomain is greater than 63 characters', async function() {
        await sanitizeAndValidate.isValidDomain(`
            moarsubdomainmoarubdomainmoarsmoarmoarsubdominmoaarsanmoarsubdom.com
        `);
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when TLD is greater than 63 characters', async function() {
        await sanitizeAndValidate.isValidDomain(`
            test.topleveltopleveltopleveltopleveltopvelveltopleveltopleveltopleve
        `);
        sinon.assert.notCalled(spy);
    })

    it('should pass regex check when period character at the end of TLD', async function() {
        await sanitizeAndValidate.isValidDomain('example.com.');
        sinon.assert.calledOnce(spy);
    })

    it('should fail regex check when non-valid character contained in subdomain', async function() {
        await sanitizeAndValidate.isValidDomain('fail*^^%&.com');
        sinon.assert.notCalled(spy);
    })

    it('should fail regex check when non-valid character contained in TLD', async function() {
        await sanitizeAndValidate.isValidDomain('fail.c$%*&m');
        sinon.assert.notCalled(spy);
    })
});

describe("Email Address Local Part Validation", function() {

    it("should pass when local part is contains valid characters", function() {
        const result = sanitizeAndValidate.isValidLocal("my!2$3.e`M-#%&'*+/=?^{|}~");
        assert.equal(result, true);
    })

    it("should pass when local part contains an invalid character", function() {
        const result = sanitizeAndValidate.isValidLocal(String.raw`eMa1l.te@st`);
        assert.equal(result, false);
    })

    it("should pass when local part is length 1 containing valid character", function() {
        const result = sanitizeAndValidate.isValidLocal("c");
        assert.equal(result, true);
    })

    it("should fail when local part is empty string", function() {
        const result = sanitizeAndValidate.isValidLocal("");
        assert.equal(result, false);
    })

    it("should fail when local part is greater than 64 characters", function() {
        const result = sanitizeAndValidate.isValidLocal("abcdef.123456778.ABCDEFGHIJKLMNOPQRSTUVwXyZ.901234abc789.65.4321i");
        assert.equal(result, false);
    })

    it("should pass when local part contains valid double quote substrings", function() {
        const result = sanitizeAndValidate.isValidLocal(String.raw`eMa1l.te"@][]"st`);
        assert.equal(result, true);
    })

    it("should pass when local part contains valid backslash quote", function() {
        const result = sanitizeAndValidate.isValidLocal(String.raw`eMa1l.te\ist`);
        assert.equal(result, true);
    })

    it("should fail when local part contains invalid double quote", function() {
        const result = sanitizeAndValidate.isValidLocal(String.raw`eMa1l.te"st`);
        assert.equal(result, false);
    })

    it("should fail when local part contains invalid backslash quote", function() {
        const result = sanitizeAndValidate.isValidLocal("eMa1l.test\\");
        assert.equal(result, false);
    })

    it("should fail when local part contains unquoted repeated period", function() {
        const result = sanitizeAndValidate.isValidLocal("eMa1l..test");
        assert.equal(result, false);
    })

    it("should fail when local part contains unquoted repeated period", function() {
        const result = sanitizeAndValidate.isValidLocal("eMa1l..test");
        assert.equal(result, false);
    })

    it("should fail when local part contains a period at the start of the string", function() {
        const result = sanitizeAndValidate.isValidLocal(".eMa1l.test");
        assert.equal(result, false);
    })

    it("should fail when local part contains a period at the end of the string", function() {
        const result = sanitizeAndValidate.isValidLocal("eMa1l.test.");
        assert.equal(result, false);
    })

    it("should pass when local part contains repeated periods with one period quoted", function() {
        const result = sanitizeAndValidate.isValidLocal(String.raw`eMa1l\..test`);
        assert.equal(result, true);
    })

    it("should pass when local part contains repeated periods in double quotes", function() {
        const result = sanitizeAndValidate.isValidLocal(String.raw`eMa1l.".."test`);
        assert.equal(result, true);
    })

    it("should pass when local part contains backslash-quoted control character", function() {
        const result = sanitizeAndValidate.isValidLocal("eMa1l.test\\\x00");
        assert.equal(result, true);
    })

    it("should pass when local part contains double-quoted control character", function() {
        const result = sanitizeAndValidate.isValidLocal(`eMa1l.te"l\np"st`);
        assert.equal(result, true);
    })

    it("should fail when local part contains unquoted control character", function() {
        const result = sanitizeAndValidate.isValidLocal(`eMa1l.te\nst`);
        assert.equal(result, false);
    })

    it("should fail when local part ends in a space character", function() {
        const result = sanitizeAndValidate.isValidLocal("eMa1l.test ");
        assert.equal(result, false);
    })

    it("should pass when local part ends in a backslash-quoted space character", function() {
        const result = sanitizeAndValidate.isValidLocal(String.raw`eMa1l.test\ `);
        assert.equal(result, true);
    })
})

describe("Full Email Address Validation", function() {
    let spy = sinon.spy(sanitizeAndValidate, "isValidLocal");

    beforeEach(() => {
        spy.resetHistory();
    })

    it("should pass the minimum character check when email address is 6 characters", async function() {
        await sanitizeAndValidate.isValidFullEmailAddress("a@b.cd");
        sinon.assert.calledOnce(spy);
    })

    it("should fail the minimum character check when email address is less than 6 characters", async function() {
        await sanitizeAndValidate.isValidFullEmailAddress("a@b.c");
        sinon.assert.notCalled(spy);
    })

    it("should pass the maximum character check when email address is 320 characters", async function() {
        await sanitizeAndValidate.isValidFullEmailAddress(String.raw`
            thetestingasthetester.mytestingthetesterfortestingasmytesttester@mydomain123456789.longsubdomaintotestthelongsubdomain123456789-mylongsubdomainfortestingthelongtestforthetestertotestthelongsubdomain.moretestingthetestforthelonfgsubdomain123456984-mylongtestforthetesterforthesubdomaintotestthetesterfortestingthetest.xyz
        `);
        sinon.assert.calledOnce(spy);
    })

    it("should fail the maximum character check when email address is greater than 320 characters", async function() {
        await sanitizeAndValidate.isValidFullEmailAddress(String.raw`
            thetestingastthetester.mytestingthetesterfortestingasmytesttester@mydomain123456789.longsubdomaintotestthelongsubdomain123456789-mylongsubdomainfortestingthelongtestforthetestertotestthelongsubdomain.moretestingthetestforthelonfgsubdomain123456984-mylongtestforthetesterforthesubdomaintotestthetesterfortestingthetest.xyz
        `);
        sinon.assert.notCalled(spy);
    })

    it("should pass the regex check when email address contains valid quoted '@' symbols", async function() {
        await sanitizeAndValidate.isValidFullEmailAddress(String.raw`
            the"@testforthe"test@the"myt@est"for@mytest.org
        `);
        sinon.assert.calledOnce(spy);
    })

    it("should pass the regex check when email address contains valid backslash-quoted '@' symbols", async function() {
        await sanitizeAndValidate.isValidFullEmailAddress(String.raw`
            mytest\@the@mytest.org
        `);
        sinon.assert.calledOnce(spy);
    })

    it("should fail the regex check when email address contains multiple unquoted '@' symbols", async function() {
        await sanitizeAndValidate.isValidFullEmailAddress(String.raw`
            the"@testforthe"test@the"myt@est"for\@to@test@mytest.com
        `);
        sinon.assert.notCalled(spy);
    })

    it("should fail the regex check when email address contains 0 unquoted '@' symbols", async function() {
        await sanitizeAndValidate.isValidFullEmailAddress(String.raw`
            forthe"te@st"thatmytest.xyz
        `);
        sinon.assert.notCalled(spy);
    })

    it("should fail the regex check when email address does not contain local part", async function() {
        await sanitizeAndValidate.isValidFullEmailAddress("@mytest");
        sinon.assert.notCalled(spy);
    })

    it("should fail the regex check when email address does not contain domain", async function() {
        await sanitizeAndValidate.isValidFullEmailAddress("thisismy@");
        sinon.assert.notCalled(spy);
    })
})
