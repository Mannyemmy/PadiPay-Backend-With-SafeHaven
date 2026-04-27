module.exports = {
  env: {
    es6: true,
    node: true,
  },
  parserOptions: {
    ecmaVersion: 2020,
  },
  extends: ["eslint:recommended"],
  rules: {
    // Turn off stylistic nonsense
    "no-unused-vars": "off",
    "indent": "off",
    "quotes": "off",
    "semi": "off",
    "camelcase": "off",
    "quote-props": "off",
    "object-curly-spacing": "off",
    "no-trailing-spaces": "off",
    "space-before-function-paren": "off",
  },
};
