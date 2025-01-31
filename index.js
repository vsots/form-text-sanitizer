const findHTML = (str) => {
    const regex = /<script.+?>/i;
    return regex.test(str);
}

export default findHTML;
