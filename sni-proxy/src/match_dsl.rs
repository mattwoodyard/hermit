//! Request-matching mini-DSL.
//!
//! Grammar:
//!   expr    := or
//!   or      := and ( "||" and )*
//!   and     := atom ( "&&" atom )*
//!   atom    := "(" expr ")" | comparison
//!   comparison := field op string
//!   op      := "==" | "!=" | "~" | "!~"
//!   field   := "method" | "url.scheme" | "url.host" | "url.path"
//!            | "headers." <header-name>
//!   string  := '"' <chars> '"'           (supports \" and \\ escapes)
//!
//! Parsed expressions compile into a tree that evaluates against
//! `&http::Request<()>`. Regexes are compiled once at parse time.

use anyhow::{anyhow, bail, Result};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{char, multispace0},
    combinator::{map, value},
    multi::many0,
    sequence::{delimited, preceded},
    IResult,
};
use regex::Regex;

#[derive(Debug, Clone)]
pub enum Field {
    Method,
    UrlScheme,
    UrlHost,
    UrlPath,
    Header(String), // lowercased
}

#[derive(Debug)]
pub enum Expr {
    Eq(Field, String),
    Neq(Field, String),
    Match(Field, Regex),
    NotMatch(Field, Regex),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

impl Expr {
    /// Compile a DSL source into an Expr. Returns an error if the
    /// expression is malformed or a regex fails to compile.
    pub fn compile(src: &str) -> Result<Self> {
        let (rest, expr) = parse_or(src).map_err(|e| anyhow!("parse error: {e}"))?;
        let rest = rest.trim();
        if !rest.is_empty() {
            bail!("unexpected trailing input: {rest:?}");
        }
        Ok(expr)
    }

    /// Evaluate this expression against a request.
    pub fn eval(&self, req: &http::Request<()>) -> bool {
        match self {
            Expr::Eq(f, v) => field_value(f, req).is_some_and(|actual| actual == *v),
            Expr::Neq(f, v) => field_value(f, req).is_none_or(|actual| actual != *v),
            Expr::Match(f, re) => field_value(f, req).is_some_and(|actual| re.is_match(&actual)),
            Expr::NotMatch(f, re) => {
                field_value(f, req).is_none_or(|actual| !re.is_match(&actual))
            }
            Expr::And(a, b) => a.eval(req) && b.eval(req),
            Expr::Or(a, b) => a.eval(req) || b.eval(req),
        }
    }
}

/// Resolve a field reference to its value in the request.
///
/// Returns `None` when the field is not present (e.g., a missing header);
/// callers decide what that means per-operator.
fn field_value(f: &Field, req: &http::Request<()>) -> Option<String> {
    match f {
        Field::Method => Some(req.method().as_str().to_string()),
        Field::UrlScheme => req.uri().scheme_str().map(|s| s.to_string()),
        Field::UrlHost => req.uri().host().map(|s| s.to_string()),
        Field::UrlPath => Some(req.uri().path().to_string()),
        Field::Header(name) => req
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Parser (nom)
// ---------------------------------------------------------------------------

fn ws<'a, O, F>(inner: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    delimited(multispace0, inner, multispace0)
}

fn parse_or(input: &str) -> IResult<&str, Expr> {
    let (input, first) = parse_and(input)?;
    let (input, rest) = many0(preceded(ws(tag("||")), parse_and))(input)?;
    Ok((
        input,
        rest.into_iter()
            .fold(first, |acc, e| Expr::Or(Box::new(acc), Box::new(e))),
    ))
}

fn parse_and(input: &str) -> IResult<&str, Expr> {
    let (input, first) = parse_atom(input)?;
    let (input, rest) = many0(preceded(ws(tag("&&")), parse_atom))(input)?;
    Ok((
        input,
        rest.into_iter()
            .fold(first, |acc, e| Expr::And(Box::new(acc), Box::new(e))),
    ))
}

fn parse_atom(input: &str) -> IResult<&str, Expr> {
    alt((
        delimited(ws(char('(')), parse_or, ws(char(')'))),
        parse_comparison,
    ))(input)
}

fn parse_comparison(input: &str) -> IResult<&str, Expr> {
    let (input, field) = ws(parse_field)(input)?;
    let (input, op) = ws(parse_op)(input)?;
    let (input, literal) = ws(parse_string)(input)?;

    let expr = match op {
        Op::Eq => Expr::Eq(field, literal),
        Op::Neq => Expr::Neq(field, literal),
        Op::Match => match Regex::new(&literal) {
            Ok(re) => Expr::Match(field, re),
            Err(_) => {
                return Err(nom::Err::Failure(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Verify,
                )));
            }
        },
        Op::NotMatch => match Regex::new(&literal) {
            Ok(re) => Expr::NotMatch(field, re),
            Err(_) => {
                return Err(nom::Err::Failure(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Verify,
                )));
            }
        },
    };
    Ok((input, expr))
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Eq,
    Neq,
    Match,
    NotMatch,
}

fn parse_op(input: &str) -> IResult<&str, Op> {
    alt((
        value(Op::Eq, tag("==")),
        value(Op::Neq, tag("!=")),
        value(Op::NotMatch, tag("!~")),
        value(Op::Match, tag("~")),
    ))(input)
}

fn parse_field(input: &str) -> IResult<&str, Field> {
    alt((
        value(Field::Method, tag("method")),
        value(Field::UrlScheme, tag("url.scheme")),
        value(Field::UrlHost, tag("url.host")),
        value(Field::UrlPath, tag("url.path")),
        map(preceded(tag("headers."), parse_header_name), |n: String| {
            Field::Header(n.to_ascii_lowercase())
        }),
    ))(input)
}

fn parse_header_name(input: &str) -> IResult<&str, String> {
    map(
        take_while1(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        |s: &str| s.to_string(),
    )(input)
}

/// Parse a double-quoted string literal. Escapes: `\"` → `"`, `\\` → `\`.
/// Any other backslash pair (e.g. `\.`, `\d`) passes through verbatim so
/// regex metacharacters work without double-escaping.
fn parse_string(input: &str) -> IResult<&str, String> {
    let (input, _) = char('"')(input)?;
    let mut out = String::new();
    let mut chars = input.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => {
                let rest = &input[i + c.len_utf8()..];
                return Ok((rest, out));
            }
            '\\' => match chars.next() {
                Some((_, '"')) => out.push('"'),
                Some((_, '\\')) => out.push('\\'),
                Some((_, other)) => {
                    out.push('\\');
                    out.push(other);
                }
                None => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        &input[i..],
                        nom::error::ErrorKind::Escaped,
                    )));
                }
            },
            _ => out.push(c),
        }
    }
    Err(nom::Err::Error(nom::error::Error::new(
        "",
        nom::error::ErrorKind::Char,
    )))
}

