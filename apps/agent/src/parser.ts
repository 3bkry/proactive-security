import { LogEvent } from "@sentinel/core";

export interface Parser {
    parse(line: string, source: string): LogEvent | null;
}

export class GenericParser implements Parser {
    parse(line: string, source: string): LogEvent {
        return {
            source,
            timestamp: new Date(),
            raw: line,
            metadata: {},
        };
    }
}

export class RegexParser implements Parser {
    constructor(private regex: RegExp) { }

    parse(line: string, source: string): LogEvent | null {
        const match = this.regex.exec(line);
        if (!match) return null;

        return {
            source,
            timestamp: new Date(),
            raw: line,
            metadata: match.groups || {},
        };
    }
}
