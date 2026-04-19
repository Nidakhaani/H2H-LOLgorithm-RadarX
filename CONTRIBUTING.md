# Contributing to RadarX

## About
RadarX was built during **Hack2Hire 1.0** at **T John Institute of Technology**, Bengaluru (April 2026).

**Theme:** Cybersecurity  
**Team:** Nida Khaani & Team RadarX

## Development Roadmap
RadarX was built over 7 consecutive days:

- **Day 1:** Project Scaffold & Tech Stack Setup
- **Day 2:** Core Scanner & Device Fingerprinter
- **Day 3:** Security Scorecard Engine
- **Day 4:** SQLite Persistence + CLI Polish
- **Day 5:** FastAPI Backend
- **Day 6:** Full Dashboard Frontend
- **Day 7:** Deployment + Final Documentation

## How to Contribute

### Local Development
1. Clone the repository:
   ```bash
   git clone https://github.com/Nidakhaani/H2H-LOLgorithm-RadarX.git
   cd radarx
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment:
   ```bash
   cp .env.example .env
   ```

4. Run in demo mode for testing:
   ```bash
   python run.py --demo
   ```

5. Start the API for dashboard testing:
   ```bash
   python run.py --api
   ```

### Code Standards
- All Python files must include module-level docstrings
- Remove debug prints before committing
- Update `requirements.txt` if adding new dependencies
- Follow existing code style (PEP 8 compatible)
- Add type hints where practical

### Testing
- Run `python run.py --demo` to verify the full pipeline
- Run `python run.py --report` to verify database persistence
- Test in `--api` mode and verify all dashboard endpoints work

### Submitting Changes
1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes and test thoroughly
3. Commit with clear messages: `git commit -m "Brief description"`
4. Push and open a pull request with detailed description

## Support
For questions or issues, open an issue on GitHub or contact the Hack2Hire team.

---

Built with ❤️ for Hack2Hire 1.0
