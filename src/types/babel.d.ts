declare module '@babel/traverse' {
  export default function traverse(ast: any, visitor: any): void;
}

declare module '@babel/parser' {
  export function parse(code: string, options?: any): any;
}
