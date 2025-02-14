# Comprehensive Toolkit and Resources for Security Incident Response

This document provides a curated selection of tools and references to support Digital Forensics and Incident Response (DFIR) teams. DFIR professionals are tasked with investigating security incidents, collecting forensic evidence, mitigating threats, and implementing preventive controls to enhance cybersecurity resilience.

# *Memory Analysis Tools*

AVML – Portable volatile memory acquisition tool for Linux.
Evolve – Web interface for the Volatility Memory Forensics Framework.
inVtero.net – Advanced memory analysis for Windows x64 with nested hypervisor support.
LiME – Loadable Kernel Module (LKM) for Linux memory acquisition.
MalConfScan – Volatility plugin for extracting malware configuration data from memory images.
Memoryze – Free memory forensic software for acquiring and analyzing memory images.
Memoryze for Mac – Memory forensic tool for Mac systems.
MemProcFS – Virtual file system for easy visualization of physical memory.
Orochi – Open-source framework for collaborative forensic memory dump analysis.
Rekall – Open-source memory forensics framework for digital artifact extraction.
Volatility – Advanced framework for analyzing volatile memory.
Volatility 3 – Successor to Volatility, designed for modern memory analysis.
VolatilityBot – Automated tool to streamline binary extraction from memory images.
VolDiff – Malware memory footprint analysis tool.
WindowsSCOPE – Memory forensics and reverse engineering tool for Windows systems.


# *Memory Imaging Tools*

Belkasoft Live RAM Capturer – Free tool for extracting volatile memory, even with anti-debug protections.
Linux Memory Grabber – Script for acquiring Linux memory and generating Volatility profiles.
MAGNET DumpIt – Fast memory acquisition tool for Windows.
Magnet RAM Capture – Free tool for capturing physical memory on Windows systems.
OSForensics – Memory acquisition tool supporting 32-bit and 64-bit systems.

OSX Evidence Collection

Knockknock – Displays persistent scripts, binaries, and commands executing on macOS.
macOS Artifact Parsing Tool (mac_apt) – Forensic framework for rapid macOS triage.
OSX Auditor – Open-source Mac OS X forensic analysis tool.
OSX Collector – Live response collection tool derived from OSX Auditor.
The ESF Playground – Tool for real-time monitoring of Apple Endpoint Security Framework (ESF) events.


# *Other Lists*

Awesome Event IDs – Comprehensive list of security-related Windows Event IDs.
Awesome Forensics – Curated collection of forensic analysis tools and resources.
Didier Stevens Suite – Collection of forensic and malware analysis utilities.
Eric Zimmerman Tools – Forensic toolset developed by Eric Zimmerman.
List of various Security APIs – Aggregated list of public JSON security APIs.


# *Other Tools*

Cortex – Analyzes observables like IPs, domains, and file hashes using a web interface or API.
Crits – Web-based threat intelligence and analytic engine.
Diffy – Netflix’s DFIR tool for cloud instance triage.
domfind – Python DNS crawler for domain name identification.
Fileintel – Hash-based file intelligence lookup tool.
HELK – Open-source threat hunting platform.
Hindsight – Chrome/Chromium browser forensic history analysis tool.
Hostintel – Host-based intelligence collection tool.
imagemounter – Command-line utility for mounting forensic disk images.
Kansa – Modular PowerShell framework for incident response.
MFT Browser – MFT directory tree reconstruction tool.
Munin – Online hash analysis tool integrated with multiple sources.
PowerSponse – PowerShell module for security incident response.
PyaraScanner – Multi-threaded YARA scanning script.
rastrea2r – YARA-based scanner for disks and memory.
RaQet – Remote forensic triage tool for disk analysis.
Raccine – Ransomware protection tool.
Scout2 – AWS security assessment tool.
Stalk – MySQL forensic investigation tool.
Stenographer – High-speed packet capture and retrieval tool.
sqhunter – Osquery-based threat hunting tool.
sysmon-config – Default high-quality event tracing Sysmon configuration.
sysmon-modular – Modular repository of Sysmon configuration templates.
traceroute-circl – Extended traceroute tool for CSIRTs.
X-Ray 2.0 – Malware submission tool for antivirus vendors.

# *Analysis Tools*

AVML - A portable volatile memory acquisition tool for Linux.
Evolve - Web interface for the Volatility Memory Forensics Framework.
inVtero.net - Advanced memory analysis for Windows x64 with nested hypervisor support.
LiME - Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, formerly called DMD.
MalConfScan - MalConfScan is a Volatility plugin extracts configuration data of known malware. Volatility is an open-source memory forensics framework for incident response and malware analysis. This tool searches for malware in memory images and dumps configuration data. In addition, this tool has a function to list strings to which malicious code refers.
Memoryze - Free memory forensic software that helps incident responders find evil in live memory. Memoryze can acquire and/or analyze memory images, and on live systems, can include the paging file in its analysis.
Memoryze for Mac - Memoryze for Mac is Memoryze but then for Macs. A lower number of features, however.
[MemProcFS] (https://github.com/ufrisk/MemProcFS) - MemProcFS is an easy and convenient way of viewing physical memory as files in a virtual file system.
Orochi - Orochi is an open source framework for collaborative forensic memory dump analysis.
Rekall - Open source tool (and library) for the extraction of digital artifacts from volatile memory (RAM) samples.
Volatility - Advanced memory forensics framework.
Volatility 3 - The volatile memory extraction framework (successor of Volatility)
VolatilityBot - Automation tool for researchers cuts all the guesswork and manual tasks out of the binary extraction phase, or to help the investigator in the first steps of performing a memory analysis investigation.
VolDiff - Malware Memory Footprint Analysis based on Volatility.
WindowsSCOPE - Memory forensics and reverse engineering tool used for analyzing volatile memory offering the capability of analyzing the Windows kernel, drivers, DLLs, and virtual and physical memory.
Memory Imaging Tools
Belkasoft Live RAM Capturer - Tiny free forensic tool to reliably extract the entire content of the computer’s volatile memory – even if protected by an active anti-debugging or anti-dumping system.
Linux Memory Grabber - Script for dumping Linux memory and creating Volatility profiles.
MAGNET DumpIt - Fast memory acquisition tool for Windows (x86, x64, ARM64). Generate full memory crash dumps of Windows machines.
Magnet RAM Capture - Free imaging tool designed to capture the physical memory of a suspect’s computer. Supports recent versions of Windows.
OSForensics - Tool to acquire live memory on 32-bit and 64-bit systems. A dump of an individual process’s memory space or physical memory dump can be done.
OSX Evidence Collection
Knockknock - Displays persistent items(scripts, commands, binaries, etc.) that are set to execute automatically on OSX.
macOS Artifact Parsing Tool (mac_apt) - Plugin based forensics framework for quick mac triage that works on live machines, disk images or individual artifact files.
OSX Auditor - Free Mac OS X computer forensics tool.
OSX Collector - OSX Auditor offshoot for live response.
The ESF Playground - A tool to view the events in Apple Endpoint Security Framework (ESF) in real time.

# *Other Tools*

Cortex - Cortex allows you to analyze observables such as IP and email addresses, URLs, domain names, files or hashes one by one or in bulk mode using a Web interface. Analysts can also automate these operations using its REST API.
Crits - Web-based tool which combines an analytic engine with a cyber threat database.
Diffy - DFIR tool developed by Netflix's SIRT that allows an investigator to quickly scope a compromise across cloud instances (Linux instances on AWS, currently) during an incident and efficiently triaging those instances for followup actions by showing differences against a baseline.
domfind - Python DNS crawler for finding identical domain names under different TLDs.
Fileintel - Pull intelligence per file hash.
HELK - Threat Hunting platform.
Hindsight - Internet history forensics for Google Chrome/Chromium.
Hostintel - Pull intelligence per host.
imagemounter - Command line utility and Python package to ease the (un)mounting of forensic disk images.
Kansa - Modular incident response framework in PowerShell.
MFT Browser - MFT directory tree reconstruction & record info.
Munin - Online hash checker for VirusTotal and other services.
PowerSponse - PowerSponse is a PowerShell module focused on targeted containment and remediation during security incident response.
PyaraScanner - Very simple multi-threaded many-rules to many-files YARA scanning Python script for malware zoos and IR.
rastrea2r - Allows one to scan disks and memory for IOCs using YARA on Windows, Linux and OS X.
RaQet - Unconventional remote acquisition and triaging tool that allows triage a disk of a remote computer (client) that is restarted with a purposely built forensic operating system.
Raccine - A Simple Ransomware Protection
Stalk - Collect forensic data about MySQL when problems occur.
Scout2 - Security tool that lets Amazon Web Services administrators assess their environment's security posture.
Stenographer - Packet capture solution which aims to quickly spool all packets to disk, then provide simple, fast access to subsets of those packets. It stores as much history as it possible, managing disk usage, and deleting when disk limits are hit. It's ideal for capturing the traffic just before and during an incident, without the need explicit need to store all of the network traffic.
sqhunter - Threat hunter based on osquery and Salt Open (SaltStack) that can issue ad-hoc or distributed queries without the need for osquery's tls plugin. sqhunter allows you to query open network sockets and check them against threat intelligence sources.
sysmon-config - Sysmon configuration file template with default high-quality event tracing
sysmon-modular - A repository of sysmon configuration modules
traceroute-circl - Extended traceroute to support the activities of CSIRT (or CERT) operators. Usually CSIRT team have to handle incidents based on IP addresses received. Created by Computer Emergency Response Center Luxembourg.
X-Ray 2.0 - Windows utility (poorly maintained or no longer maintained) to submit virus samples to AV vendors.

# *Playbooks*

AWS Incident Response Runbook Samples - AWS IR Runbook Samples meant to be customized per each entity using them. The three samples are: "DoS or DDoS attack", "credential leakage", and "unintended access to an Amazon S3 bucket".
Counteractive Playbooks - Counteractive PLaybooks collection.
GuardSIght Playbook Battle Cards - A collection of Cyber Incident Response Playbook Battle Cards
IRM - Incident Response Methodologies by CERT Societe Generale.
PagerDuty Incident Response Documentation - Documents that describe parts of the PagerDuty Incident Response process. It provides information not only on preparing for an incident, but also what to do during and after. Source is available on GitHub.
Phantom Community Playbooks - Phantom Community Playbooks for Splunk but also customizable for other use.
ThreatHunter-Playbook - Playbook to aid the development of techniques and hypothesis for hunting campaigns.
Process Dump Tools
Microsoft ProcDump - Dumps any running Win32 processes memory image on the fly.
PMDump - Tool that lets you dump the memory contents of a process to a file without stopping the process.

# *Sandboxing/Reversing Tools*

Any Run - Interactive online malware analysis service for dynamic and static research of most types of threats using any environment.
CAPA - detects capabilities in executable files. You run it against a PE, ELF, .NET module, or shellcode file and it tells you what it thinks the program can do.
CAPEv2 - Malware Configuration And Payload Extraction.
Cuckoo - Open Source Highly configurable sandboxing tool.
Cuckoo-modified - Heavily modified Cuckoo fork developed by community.
Cuckoo-modified-api - Python library to control a cuckoo-modified sandbox.
Cutter - Free and Open Source Reverse Engineering Platform powered by rizin.
Ghidra - Software Reverse Engineering Framework.
Hybrid-Analysis - Free powerful online sandbox by CrowdStrike.
Intezer - Intezer Analyze dives into Windows binaries to detect micro-code similarities to known threats, in order to provide accurate yet easy-to-understand results.
Joe Sandbox (Community) - Joe Sandbox detects and analyzes potential malicious files and URLs on Windows, Android, Mac OS, Linux, and iOS for suspicious activities; providing comprehensive and detailed analysis reports.
Mastiff - Static analysis framework that automates the process of extracting key characteristics from a number of different file formats.
Metadefender Cloud - Free threat intelligence platform providing multiscanning, data sanitization and vulnerability assessment of files.
Radare2 - Reverse engineering framework and command-line toolset.
Reverse.IT - Alternative domain for the Hybrid-Analysis tool provided by CrowdStrike.
Rizin - UNIX-like reverse engineering framework and command-line toolset
StringSifter - A machine learning tool that ranks strings based on their relevance for malware analysis.
Threat.Zone - Cloud based threat analysis platform which include sandbox, CDR and interactive analysis for researchers.
Valkyrie Comodo - Valkyrie uses run-time behavior and hundreds of features from a file to perform analysis.
Viper - Python based binary analysis and management framework, that works well with Cuckoo and YARA.
Virustotal - Free online service that analyzes files and URLs enabling the identification of viruses, worms, trojans and other kinds of malicious content detected by antivirus engines and website scanners.
Visualize_Logs - Open source visualization library and command line tools for logs (Cuckoo, Procmon, more to come).
Yomi - Free MultiSandbox managed and hosted by Yoroi.
Scanner Tools
Fenrir - Simple IOC scanner. It allows scanning any Linux/Unix/OSX system for IOCs in plain bash. Created by the creators of THOR and LOKI.
LOKI - Free IR scanner for scanning endpoint with yara rules and other indicators(IOCs).
Spyre - Simple YARA-based IOC scanner written in Go
Timeline Tools
Aurora Incident Response - Platform developed to build easily a detailed timeline of an incident.
Highlighter - Free Tool available from Fire/Mandiant that will depict log/text file that can highlight areas on the graphic, that corresponded to a key word or phrase. Good for time lining an infection and what was done post compromise.
Morgue - PHP Web app by Etsy for managing postmortems.
Plaso - a Python-based backend engine for the tool log2timeline.
Timesketch - Open source tool for collaborative forensic timeline analysis.


# *Windows Evidence Collection*

AChoir - Framework/scripting tool to standardize and simplify the process of scripting live acquisition utilities for Windows.
Crowd Response - Lightweight Windows console application designed to aid in the gathering of system information for incident response and security engagements. It features numerous modules and output formats.
Cyber Triage - Cyber Triage has a lightweight collection tool that is free to use. It collects source files (such as registry hives and event logs), but also parses them on the live host so that it can also collect the executables that the startup items, scheduled, tasks, etc. refer to. It's output is a JSON file that can be imported into the free version of Cyber Triage. Cyber Triage is made by Sleuth Kit Labs, which also makes Autopsy.
DFIR ORC - DFIR ORC is a collection of specialized tools dedicated to reliably parse and collect critical artifacts such as the MFT, registry hives or event logs. DFIR ORC collects data, but does not analyze it: it is not meant to triage machines. It provides a forensically relevant snapshot of machines running Microsoft Windows. The code can be found on GitHub.
FastIR Collector - Tool that collects different artifacts on live Windows systems and records the results in csv files. With the analyses of these artifacts, an early compromise can be detected.
Fibratus - Tool for exploration and tracing of the Windows kernel.
Hoarder - Collecting the most valuable artifacts for forensics or incident response investigations.
IREC - All-in-one IR Evidence Collector which captures RAM Image, $MFT, EventLogs, WMI Scripts, Registry Hives, System Restore Points and much more. It is FREE, lightning fast and easy to use.
Invoke-LiveResponse - Invoke-LiveResponse is a live response tool for targeted collection.
IOC Finder - Free tool from Mandiant for collecting host system data and reporting the presence of Indicators of Compromise (IOCs). Support for Windows only. No longer maintained. Only fully supported up to Windows 7 / Windows Server 2008 R2.
IRTriage - Incident Response Triage - Windows Evidence Collection for Forensic Analysis.
KAPE - Kroll Artifact Parser and Extractor (KAPE) by Eric Zimmerman. A triage tool that finds the most prevalent digital artifacts and then parses them quickly. Great and thorough when time is of the essence.
LOKI - Free IR scanner for scanning endpoint with yara rules and other indicators(IOCs).
MEERKAT - PowerShell-based triage and threat hunting for Windows.
Panorama - Fast incident overview on live Windows systems.
PowerForensics - Live disk forensics platform, using PowerShell.
PSRecon - PSRecon gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team. The data can be pushed to a share, sent over email, or retained locally.
RegRipper - Open source tool, written in Perl, for extracting/parsing information (keys, values, data) from the Registry and presenting it for analysis.

This compilation serves as a foundational resource for DFIR practitioners, enabling them to enhance their investigative capabilities and improve incident response efficacy. Continuous learning and staying updated with evolving threat landscapes remain crucial for professionals in this domain.
