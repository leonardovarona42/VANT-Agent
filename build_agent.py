#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║                     VANT-SIEM OpenSearch Agent                          ║
║                      Build Script (PyInstaller)                          ║
║                                                                           ║
║  Script: build_agent.py                                                  ║
║  Purpose: Compile OpenSearch agent to standalone executables           ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from datetime import datetime


class Colors:
    """ANSI color codes"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'
    RESET = '\033[0m'


def print_header(title):
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'═' * 70}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}  {title}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'═' * 70}{Colors.END}\n")


def print_success(msg):
    print(f"  {Colors.GREEN}✓{Colors.END} {msg}")


def print_error(msg):
    print(f"  {Colors.RED}✗{Colors.END} {msg}")


def print_warning(msg):
    print(f"  {Colors.YELLOW}⚠{Colors.END} {msg}")


def print_info(msg):
    print(f"  {Colors.BLUE}ℹ{Colors.END} {msg}")


def check_pyinstaller():
    """Check if PyInstaller is installed"""
    try:
        import PyInstaller
        print_success(f"PyInstaller installed: {PyInstaller.__version__}")
        return True
    except ImportError:
        print_error("PyInstaller is not installed")
        print_info("Installing PyInstaller...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
            print_success("PyInstaller installed successfully")
            return True
        except:
            print_error("Failed to install PyInstaller")
            return False


def check_dependencies():
    """Check required dependencies"""
    print_header("Checking Dependencies")
    
    required = ['yaml', 'requests']
    all_ok = True
    
    for dep in required:
        try:
            __import__(dep)
            print_success(f"{dep}: installed")
        except ImportError:
            print_warning(f"{dep}: not installed, installing...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
                print_success(f"{dep}: installed")
            except:
                print_error(f"Failed to install {dep}")
                all_ok = False
    
    return all_ok


def clean_build():
    """Clean previous build directories"""
    print_info("Cleaning previous builds...")
    
    dirs_to_clean = ['build', 'dist', '__pycache__']
    script_dir = Path(__file__).parent
    
    for dir_name in dirs_to_clean:
        dir_path = script_dir / dir_name
        if dir_path.exists():
            shutil.rmtree(dir_path)
            print_success(f"Removed: {dir_name}/")
    
    # Also clean spec files
    for spec_file in script_dir.glob('*.spec'):
        spec_file.unlink()
        print_success(f"Removed: {spec_file.name}")


def build_executable(script_name, output_name, icon=None, onefile=True, console=True):
    """Build a single executable"""
    print_info(f"Building {output_name}...")
    
    script_path = Path(__file__).parent / script_name
    
    if not script_path.exists():
        print_error(f"Script not found: {script_name}")
        return False
    
    # Build command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", output_name,
        "--clean",
    ]
    
    # Onefile or onedir
    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")
    
    # Console window
    if console:
        cmd.append("--console")
    else:
        cmd.append("--noconsole")
    
    # Icon
    if icon:
        cmd.extend(["--icon", icon])
    
    # Add data files (config). Use platform separator (; on Windows, : on Unix).
    add_data_sep = os.pathsep
    cmd.extend(["--add-data", f"config.example.yaml{add_data_sep}."])
    
    # Hidden imports
    cmd.extend(["--hidden-import", "yaml"])
    cmd.extend(["--hidden-import", "requests"])
    
    # Exclude unnecessary modules
    cmd.extend(["--exclude-module", "pytest"])
    cmd.extend(["--exclude-module", "setuptools"])
    cmd.extend(["--exclude-module", "pip"])
    
    # Output directory
    cmd.extend(["--distpath", "dist"])
    cmd.extend(["--workpath", "build"])
    
    # Script
    cmd.append(str(script_path))
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print_success(f"{output_name} built successfully!")
            return True
        else:
            print_error(f"Build failed for {output_name}")
            print(result.stderr[-500:] if len(result.stderr) > 500 else result.stderr)
            return False
            
    except Exception as e:
        print_error(f"Error building {output_name}: {e}")
        return False


def copy_runtime_files(output_name):
    """Copy necessary runtime files to dist"""
    print_info("Copying runtime files...")
    
    script_dir = Path(__file__).parent
    dist_dir = script_dir / "dist" / output_name
    
    if not dist_dir.exists():
        print_warning("Dist directory not found")
        return
    
    # If onefile build, dist_dir is a file. Place runtime files alongside it.
    if dist_dir.is_file():
        config_dir = dist_dir.parent
    else:
        config_dir = dist_dir
        if not config_dir.exists():
            config_dir.mkdir(parents=True)
    
    # Copy config example
    config_src = script_dir / "config.example.yaml"
    config_dst = config_dir / "config.yaml"
    
    if config_src.exists() and not config_dst.exists():
        shutil.copy2(config_src, config_dst)
        print_success("Copied config.example.yaml to config.yaml")
    
    # Copy other scripts that might be needed
    helper_scripts = ['opensearchcheck.py', 'opensearchmover.py']
    for script in helper_scripts:
        src = script_dir / script
        if src.exists():
            dst = config_dir / script
            shutil.copy2(src, dst)
            print_success(f"Copied {script}")


def create_distribution_package(output_name):
    """Create a ZIP distribution package"""
    print_info("Creating distribution package...")
    
    script_dir = Path(__file__).parent
    dist_dir = script_dir / "dist" / output_name
    
    if not dist_dir.exists():
        print_error("Dist directory not found")
        return False
    
    # Create ZIP
    zip_name = f"VANT-SIEM-Agent-{output_name}-{datetime.now().strftime('%Y%m%d')}"
    zip_path = script_dir / "dist" / zip_name

    # If onefile build, dist_dir is a file. Zip the file plus runtime assets
    if dist_dir.is_file():
        import zipfile
        with zipfile.ZipFile(str(zip_path) + ".zip", "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(dist_dir, dist_dir.name)
            # Include runtime files copied alongside the binary
            for extra in ["config.yaml", "opensearchcheck.py", "opensearchmover.py"]:
                extra_path = dist_dir.parent / extra
                if extra_path.exists():
                    zf.write(extra_path, extra_path.name)
    else:
        shutil.make_archive(str(zip_path), 'zip', dist_dir)
    
    print_success(f"Package created: {zip_name}.zip")
    return True


def build_all():
    """Build all executables"""
    print_header("VANT-SIEM Agent Build System")
    
    print(f"Build started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Check dependencies
    if not check_dependencies():
        print_error("Dependency check failed")
        sys.exit(1)
    
    # Check PyInstaller
    if not check_pyinstaller():
        print_error("PyInstaller check failed")
        sys.exit(1)
    
    # Clean
    clean_build()
    
    # Build main agent
    print_header("Building Main Agent")
    
    if not build_executable('agent.py', 'VANT-SIEM-Agent', onefile=True, console=True):
        print_error("Failed to build main agent")
        sys.exit(1)
    
    copy_runtime_files('VANT-SIEM-Agent')
    
    # Build config checker
    print_header("Building Config Checker")
    
    if not build_executable('opensearchcheck.py', 'VANT-SIEM-Check', onefile=True, console=True):
        print_warning("Config checker build failed, continuing...")
    
    # Build server mover
    print_header("Building Server Mover")
    
    if not build_executable('opensearchmover.py', 'VANT-SIEM-Mover', onefile=True, console=True):
        print_warning("Server mover build failed, continuing...")
    
    # Create distribution packages
    print_header("Creating Distribution Packages")
    create_distribution_package('VANT-SIEM-Agent')
    
    # Summary
    print_header("Build Complete!")
    
    print_success("Build completed successfully!")
    print()
    print("Output files:")
    print("  - dist/VANT-SIEM-Agent/")
    print("  - dist/VANT-SIEM-Check/ (optional)")
    print("  - dist/VANT-SIEM-Mover/ (optional)")
    print()
    print("To run:")
    print("  - ./dist/VANT-SIEM-Agent/VANT-SIEM-Agent.exe --config config.yaml")
    print("  - ./dist/VANT-SIEM-Check/VANT-SIEM-Check.exe --config config.yaml")
    print("  - ./dist/VANT-SIEM-Mover/VANT-SIEM-Mover.exe --host newserver.local")


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='VANT-SIEM Agent Build Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s              # Build all executables
  %(prog)s --agent      # Build only the main agent
  %(prog)s --check      # Build only the config checker
  %(prog)s --mover      # Build only the server mover
  %(prog)s --clean      # Clean previous builds
        """
    )
    
    parser.add_argument(
        '--agent',
        action='store_true',
        help='Build main agent only'
    )
    
    parser.add_argument(
        '--check',
        action='store_true',
        help='Build config checker only'
    )
    
    parser.add_argument(
        '--mover',
        action='store_true',
        help='Build server mover only'
    )
    
    parser.add_argument(
        '--clean',
        action='store_true',
        help='Clean previous builds'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Build all executables (default)'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("╔═══════════════════════════════════════════════════════════════════════╗")
    print("║                                                                       ║")
    print("║               VANT-SIEM OpenSearch Agent Builder                     ║")
    print("║                     PyInstaller Compilation                          ║")
    print("║                                                                       ║")
    print("╚═══════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    
    # Handle clean
    if args.clean:
        clean_build()
        print_success("Build directories cleaned")
        sys.exit(0)
    
    # Default: build all
    if not any([args.agent, args.check, args.mover]):
        build_all()
        sys.exit(0)
    
    # Check dependencies
    if not check_dependencies():
        print_error("Dependency check failed")
        sys.exit(1)
    
    if not check_pyinstaller():
        print_error("PyInstaller check failed")
        sys.exit(1)
    
    # Build selected
    if args.agent:
        build_executable('agent.py', 'VANT-SIEM-Agent', onefile=True, console=True)
        copy_runtime_files('VANT-SIEM-Agent')
    
    if args.check:
        build_executable('opensearchcheck.py', 'VANT-SIEM-Check', onefile=True, console=True)
    
    if args.mover:
        build_executable('opensearchmover.py', 'VANT-SIEM-Mover', onefile=True, console=True)
    
    print_success("Build completed!")


if __name__ == '__main__':
    main()
