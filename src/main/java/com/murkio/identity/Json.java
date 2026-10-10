package com.murkio.identity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small JSON reader and writer, so the SDK adds no dependency to the
 * application. Objects become {@code Map<String, Object>}, arrays {@code List<Object>},
 * numbers {@code Long} or {@code Double}. The writer escapes {@code <}, {@code >},
 * {@code &} and the U+2028/U+2029 separators, so its output is safe inside a
 * {@code <script>} element.
 */
final class Json {
    private static final int MAX_DEPTH = 64;

    private final String text;
    private int position;

    private Json(String text) {
        this.text = text;
    }

    static Object parse(String text) {
        Json reader = new Json(text);
        Object value = reader.value(0);
        reader.whitespace();
        if (reader.position != text.length()) {
            throw new IllegalArgumentException("unexpected data after the JSON value");
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> parseObject(String text) {
        Object value = parse(text);
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("not a JSON object");
        }
        return (Map<String, Object>) value;
    }

    private void whitespace() {
        while (position < text.length() && " \t\r\n".indexOf(text.charAt(position)) >= 0) {
            position++;
        }
    }

    private char next() {
        if (position >= text.length()) {
            throw new IllegalArgumentException("unexpected end of JSON");
        }
        return text.charAt(position++);
    }

    private void expect(String literal) {
        if (!text.startsWith(literal, position)) {
            throw new IllegalArgumentException("invalid JSON at " + position);
        }
        position += literal.length();
    }

    private Object value(int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("JSON nested too deep");
        }
        whitespace();
        if (position >= text.length()) {
            throw new IllegalArgumentException("unexpected end of JSON");
        }
        char c = text.charAt(position);
        switch (c) {
            case '{':
                return object(depth);
            case '[':
                return array(depth);
            case '"':
                return string();
            case 't':
                expect("true");
                return Boolean.TRUE;
            case 'f':
                expect("false");
                return Boolean.FALSE;
            case 'n':
                expect("null");
                return null;
            default:
                return number();
        }
    }

    private Map<String, Object> object(int depth) {
        Map<String, Object> output = new LinkedHashMap<>();
        position++;
        whitespace();
        if (position < text.length() && text.charAt(position) == '}') {
            position++;
            return output;
        }
        while (true) {
            whitespace();
            if (next() != '"') {
                throw new IllegalArgumentException("expected a string key at " + (position - 1));
            }
            position--;
            String key = string();
            whitespace();
            if (next() != ':') {
                throw new IllegalArgumentException("expected ':' at " + (position - 1));
            }
            output.put(key, value(depth + 1));
            whitespace();
            char c = next();
            if (c == '}') {
                return output;
            }
            if (c != ',') {
                throw new IllegalArgumentException("expected ',' or '}' at " + (position - 1));
            }
        }
    }

    private List<Object> array(int depth) {
        List<Object> output = new ArrayList<>();
        position++;
        whitespace();
        if (position < text.length() && text.charAt(position) == ']') {
            position++;
            return output;
        }
        while (true) {
            output.add(value(depth + 1));
            whitespace();
            char c = next();
            if (c == ']') {
                return output;
            }
            if (c != ',') {
                throw new IllegalArgumentException("expected ',' or ']' at " + (position - 1));
            }
        }
    }

    private String string() {
        StringBuilder output = new StringBuilder();
        position++;
        while (true) {
            char c = next();
            if (c == '"') {
                return output.toString();
            }
            if (c < 0x20) {
                throw new IllegalArgumentException("control character in a JSON string");
            }
            if (c != '\\') {
                output.append(c);
                continue;
            }
            char escape = next();
            switch (escape) {
                case '"', '\\', '/' -> output.append(escape);
                case 'b' -> output.append('\b');
                case 'f' -> output.append('\f');
                case 'n' -> output.append('\n');
                case 'r' -> output.append('\r');
                case 't' -> output.append('\t');
                case 'u' -> {
                    if (position + 4 > text.length()) {
                        throw new IllegalArgumentException("invalid unicode escape");
                    }
                    output.append((char) Integer.parseInt(text.substring(position, position + 4), 16));
                    position += 4;
                }
                default -> throw new IllegalArgumentException("invalid escape in a JSON string");
            }
        }
    }

    private Object number() {
        int start = position;
        while (position < text.length() && "+-0123456789.eE".indexOf(text.charAt(position)) >= 0) {
            position++;
        }
        String raw = text.substring(start, position);
        if (raw.isEmpty()) {
            throw new IllegalArgumentException("invalid JSON at " + start);
        }
        if (raw.indexOf('.') < 0 && raw.indexOf('e') < 0 && raw.indexOf('E') < 0) {
            try {
                return Long.parseLong(raw);
            } catch (NumberFormatException ignored) {
                // falls through to a double (a huge integer)
            }
        }
        return Double.parseDouble(raw);
    }

    static String write(Object value) {
        StringBuilder output = new StringBuilder();
        write(output, value);
        return output.toString();
    }

    private static void write(StringBuilder output, Object value) {
        if (value == null) {
            output.append("null");
        } else if (value instanceof String string) {
            quote(output, string);
        } else if (value instanceof Number || value instanceof Boolean) {
            output.append(value);
        } else if (value instanceof Map<?, ?> map) {
            output.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    output.append(',');
                }
                first = false;
                quote(output, String.valueOf(entry.getKey()));
                output.append(':');
                write(output, entry.getValue());
            }
            output.append('}');
        } else if (value instanceof Iterable<?> items) {
            output.append('[');
            boolean first = true;
            for (Object item : items) {
                if (!first) {
                    output.append(',');
                }
                first = false;
                write(output, item);
            }
            output.append(']');
        } else {
            quote(output, value.toString());
        }
    }

    private static void quote(StringBuilder output, String value) {
        output.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> {
                    if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == 0x2028 || c == 0x2029) {
                        output.append(String.format("\\u%04x", (int) c));
                    } else {
                        output.append(c);
                    }
                }
            }
        }
        output.append('"');
    }
}
