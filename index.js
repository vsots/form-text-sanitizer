const openAngleBracket = /<|%3c|&lt|&#0{0,6}60|&#x0{0,6}3c/gisv;
const openAngleBracketMatcher = /[<\q{%3c|&lt|&#60|&#060|&#0060|&#00060|&#000060|&#0000060|&#00000060|&#x3c|&#x03c|&#x003c|&#x0003c|&#x00003c|&#x000003c|&#x0000003c}]/gisv;
const closedAngleBracket = />|%3e|&gt|&#0{0,6}62|&#x0{0,6}3e/gisv;
const closedAngleBracketMatcher = /[>\q{%3e|&gt|&#62|&#062|&#0062|&#00062|&#000062|&#0000062|&#00000062|&#x3e|&#x03e|&#x003e|&#x0003e|&#x00003e|&#x000003e|&#x0000003e}]/gisv;
const doubleQuote = /"|%22|&quot|&#0{0,6}34|&#x0{0,6}22/gisv;
const doubleQuoteMatcher = /["\q{%22|&quot|&#34|&#034|&#0034|&#00034|&#000034|&#0000034|&#00000034|&#x22|&#x022|&#x0022|&#x00022|&#x000022|&#x0000022|&#x00000022}]/gisv;
const singleQuote = /'|%27|&apos|&#0{0,6}39|&#x0{0,6}27/gisv;
const singleQuoteMatcher = /['\q{%27|&apos|&#39|&#039|&#0039|&#00039|&#000039|&#0000039|&#00000039|&#x27|&#x027|&#x0027|&#x00027|&#x000027|&#x0000027|&#x00000027}]/gisv;
const backtick = /`|%60|&DiacriticalGrave|&#0{0,6}96|&#x0{0,6}60/gisv;
const backtickMatcher = /[`\q{%60|&DiacriticalGrave|&#96|&#096|&#0096|&#00096|&#000096|&#0000096|&#00000096|&#x60|&#x060|&#x0060|&#x00060|&#x000060|&#x0000060|&#x00000060}]/gisv;
const forwardSlash = /\/|%2F|&sol|&#0{0,6}47|&#x0{0,6}2f/gisv;


const htmlSvgReg = 
    openAngleBracketMatcher.source +
    "(?:" + 
        doubleQuoteMatcher.source + ".*?" + doubleQuoteMatcher.source + "|" +
        singleQuoteMatcher.source + ".*?" + singleQuoteMatcher.source + "|" +
        backtickMatcher.source + ".*?" + backtickMatcher.source + "|" +
        "(?!" + openAngleBracket.source + "|" + closedAngleBracket.source + ")." +
    ")*" + 
    closedAngleBracketMatcher.source + "?";

const flags = "gisv";

const finalHtmlSvgReg = new RegExp(htmlSvgReg, flags);

const findHTMLSVG = (str) => {
    const test = finalHtmlSvgReg.test(str);
    const res = test ? str.match(finalHtmlSvgReg) : [];
    return [test, res];
}

export default findHTMLSVG;
