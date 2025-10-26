# Contributing to Personal 2FA

Thank you for your interest in contributing to Personal 2FA! We welcome contributions from the community.

## 🚀 Development Setup

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/personal-2fa.git
   cd personal-2fa
   ```
3. **Install dependencies**:
   ```bash
   npm install
   ```
4. **Start development server**:
   ```bash
   npm run dev
   ```
5. **Open** http://localhost:3000 in your browser

## 🔧 Build Process

- **Development**: `npm run dev` - Starts local server
- **Build**: `npm run build` - Creates optimized build
- **Build Standalone**: `node build.js` - Creates single-file version

## 📝 Code Style

- Use **ES2022** features and modern JavaScript
- Follow **existing code patterns** and naming conventions
- Add **JSDoc comments** for functions and classes
- Use **semantic commit messages**

## 🧪 Testing

- Test your changes in **multiple browsers**
- Verify **HTTPS/localhost** requirements
- Test **import/export** functionality thoroughly
- Check **mobile responsiveness**

## 🐛 Reporting Bugs

Please use the [GitHub Issues](https://github.com/lfern/personal-2fa/issues) page to report bugs. Include:

- **Browser** and version
- **Steps to reproduce** the issue
- **Expected** vs **actual** behavior
- **Screenshots** if applicable
- **Console errors** if any

## 💡 Feature Requests

We welcome feature requests! Please:

1. **Check existing issues** first
2. **Describe the use case** clearly
3. **Explain the benefit** to users
4. **Consider security implications**

## 🔒 Security Considerations

Personal 2FA handles sensitive data. When contributing:

- **Never log** sensitive information
- **Clear sensitive data** from memory when possible
- **Follow crypto best practices**
- **Test security features** thoroughly
- **Report security issues** privately

## 📋 Pull Request Process

1. **Create feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. **Make your changes** with clear, focused commits
3. **Test thoroughly** across different browsers
4. **Update documentation** if needed
5. **Submit pull request** with clear description

### Pull Request Guidelines

- **One feature** per pull request
- **Clear description** of changes
- **Reference related issues** if applicable
- **Update README** if adding new features
- **Add tests** for new functionality when applicable

## 🏷️ Commit Message Format

Use conventional commits format:

```
type(scope): description

Examples:
feat(auth): add master password validation
fix(export): resolve QR generation issue
docs(readme): update installation instructions
style(ui): improve button spacing
```

## 📚 Documentation

When adding features:

- Update relevant **README** sections
- Add **JSDoc** comments to code
- Update **user documentation** if needed
- Consider adding **examples**

## 🌐 Internationalization

We support multiple languages:

- **Add translations** to `src/js/i18n.js`
- **Use i18n keys** for all user-facing text
- **Test language switching** functionality
- **Follow existing translation patterns**

## 💬 Questions?

- **Open an issue** for questions about contributing
- **Check existing issues** for similar questions
- **Be patient** - this is a volunteer-maintained project

## 📄 License

By contributing to Personal 2FA, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make Personal 2FA better for everyone! 🙏