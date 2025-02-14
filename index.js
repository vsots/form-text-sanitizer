
const conditions = [
    /*
    * HTML Tags (including svg)
    */
    /<script.*?>/,
    /<\/script.*?>/,
    /<body.*?>/,
    /<\/body.*?>/,
    /<a.*?>/,
    /<\/a.*?>/,
    /<svg.*?>/,
    /<img.*?>/,

    /*
    * Attributes
    */
    /src.*?=(".*?"|'.*?'|\S*.?|\S*.?(?=>))/,
    /href.*?=(".*?"|'.*?'|\S*.?|\S*.?(?=>))/,
    /alert\(.*?\)/,
    /onload.*?=(".*?"|'.*?'|\S*.?|\S*.?(?=>))/,
    /onmouseover.*?=(".*?"|'.*?'|\S*.?|\S*.?(?=>))/,
    /onerror.*?=(".*?"|'.*?'|\S*.?|\S*.?(?=>))/,

    /*
    * Methods
    */
    /fromCharCode\(.*?\)/,

    /*
    * Other
    */
    /javascript:/,
    /perl -.*?out/
]

const options = 'gisv';

const regex = new RegExp(conditions.map((exp) => exp.source).join('|'), options);


const findHTML = (str) => [regex.test(str), str.match(regex)];

export default findHTML;
