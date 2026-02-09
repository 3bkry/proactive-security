export class GenericParser {
    parse(line, source) {
        return {
            source,
            timestamp: new Date(),
            raw: line,
            metadata: {},
        };
    }
}
export class RegexParser {
    regex;
    constructor(regex) {
        this.regex = regex;
    }
    parse(line, source) {
        const match = this.regex.exec(line);
        if (!match)
            return null;
        return {
            source,
            timestamp: new Date(),
            raw: line,
            metadata: match.groups || {},
        };
    }
}
//# sourceMappingURL=parser.js.map