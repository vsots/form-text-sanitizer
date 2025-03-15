const openAngleBracket = /<|%3c|&lt|&#0{0,6}60|&#x0{0,6}3c/gisv;
const openAngleBracketMatcher = /[<\q{%3c|&lt|&#60|&#060|&#0060|&#00060|&#000060|&#0000060|&#00000060|&#x3c|&#x03c|&#x003c|&#x0003c|&#x00003c|&#x000003c|&#x0000003c}]/gisv;
const closedAngleBracket = />|%3e|&gt|&#0{0,6}62|&#x0{0,6}3e/gisv;
const closedAngleBracketMatcher = /[>\q{%3e|&gt|&#62|&#062|&#0062|&#00062|&#000062|&#0000062|&#00000062|&#x3e|&#x03e|&#x003e|&#x0003e|&#x00003e|&#x000003e|&#x0000003e}]/gisv;
const doubleQuoteMatcher = /["\q{%22|&quot|&#34|&#034|&#0034|&#00034|&#000034|&#0000034|&#00000034|&#x22|&#x022|&#x0022|&#x00022|&#x000022|&#x0000022|&#x00000022}]/gisv;
const singleQuoteMatcher = /['\q{%27|&apos|&#39|&#039|&#0039|&#00039|&#000039|&#0000039|&#00000039|&#x27|&#x027|&#x0027|&#x00027|&#x000027|&#x0000027|&#x00000027}]/gisv;
const backtickMatcher = /[`\q{%60|&DiacriticalGrave|&#96|&#096|&#0096|&#00096|&#000096|&#0000096|&#00000096|&#x60|&#x060|&#x0060|&#x00060|&#x000060|&#x0000060|&#x00000060}]/gisv;
const openBracketMatcher = /[\{\q{%7b|&lcub|&#123|&#0123|&#00123|&#000123|&#0000123|&#00000123|&#000000123|&#x7b|&#x07b|&#x007b|&#x0007b|&#x00007b|&#x000007b|&#x0000007b}]/gisv;
const closedBracketMatcher = /[\}\q{%7d|&rcub|&#125|&#0125|&#00125|&#000125|&#0000125|&#00000125|&#000000125|&#x7d|&#x07d|&#x007d|&#x0007d|&#x00007d|&#x000007d|&#x0000007d}]/gisv;

const flags = "gisv";

const htmlSvgErb = 
    "(?:" + openAngleBracketMatcher.source + ";?" + ")" + "+" +
    "(?:" + 
        doubleQuoteMatcher.source + ".*" + doubleQuoteMatcher.source + "|" +
        singleQuoteMatcher.source + ".*" + singleQuoteMatcher.source + "|" +
        backtickMatcher.source + ".*" + backtickMatcher.source + "|" +
        "(?!" + openAngleBracket.source + "|" + closedAngleBracket.source + ")." +
    ")*" + "(?:" +
        ".*" + closedAngleBracketMatcher.source + ";?" +
    ")?";

const htmlSvgErbReg = new RegExp(htmlSvgErb, flags);

const mustache = openBracketMatcher.source + ";?" + openBracketMatcher.source + ".*" + closedBracketMatcher.source + ";?" + closedBracketMatcher.source + ";?";

const mustacheReg = new RegExp(mustache, flags);

interface IntermediateResponse {
    test: Boolean;
    res: Array<string>;
    matches: Array<number>;
}

interface FinalResponse {
    originalString: string;
    suggestedString: string;
    matches: Array<string>;
}

const findHTMLSVGERB = (str: string): IntermediateResponse => {
    const test = htmlSvgErbReg.test(str);
    const res = (test ? str.match(htmlSvgErbReg) : []) as Array<string>;

    const matches = [];
    let match = htmlSvgErbReg.exec(str);
    while (match != null) {
        matches.push(match.index);
        match = htmlSvgErbReg.exec(str)
    }

    return { test, res, matches };
}

const findMustache = (str: string): IntermediateResponse => {
    const test = mustacheReg.test(str);
    const res = (test ? str.match(mustacheReg) : []) as Array<string>;

    const matches = [];
    let match = mustacheReg.exec(str);
    while (match != null) {
        matches.push(match.index);
        match = mustacheReg.exec(str);
    }

    return { test, res, matches };
}

const checkAndSanitizeString = (str: string): FinalResponse => {
    const htmlCheck = findHTMLSVGERB(str);
    let suggestedString = "";

    if (htmlCheck.test) {
        const lastIdx = htmlCheck.matches.length - 1;
        const lastSubstrStart = htmlCheck.matches[lastIdx] + htmlCheck.res[lastIdx].length;
        suggestedString = str.substring(0, htmlCheck.matches[0]) + str.substring(lastSubstrStart, str.length);
    } else suggestedString = str;

    const mustacheCheck = findMustache(suggestedString);

    if (mustacheCheck.test) {
        const lastIdx = mustacheCheck.matches.length - 1;
        const lastSubstrStart = mustacheCheck.matches[lastIdx] + mustacheCheck.res[lastIdx].length;
        suggestedString = suggestedString.substring(0, mustacheCheck.matches[0]) + suggestedString.substring(lastSubstrStart, str.length);
    }

    const matches = htmlCheck.res.concat(mustacheCheck.res);

    return { originalString: str, suggestedString, matches };
}

export default checkAndSanitizeString;
