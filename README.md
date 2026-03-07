# AbuseCVE Technical Documentation

A comprehensive Cyber Threat Intelligence platform focused on continuous Common Vulnerabilities and Exposures (CVE) monitoring, customizable filtering, and automated alerting. This document serves as the technical reference for system architecture, component interaction, and data pipeline operations.

For detailed instructions on how to operate the platform, manage filter rules, and use the Policy Query Language, please refer to the **[Usage Guide](USAGE.md)**. For advanced administrative tasks and automation using `cURL`, see the **[Administrative API Guide](ADMIN_API.md)**.

## Table of Contents
1. [System Architecture Overview](#system-architecture-overview)
2. [Core Components](#core-components)
3. [Data Processing Pipeline](#data-processing-pipeline)
4. [Worker Technical Operations](#worker-technical-operations)
5. [Component Communication Flow](#component-communication-flow)
6. [Filter Engine and Configuration](#filter-engine-and-configuration)
7. [Deployment and Initialization](#deployment-and-initialization)

## System Architecture Overview

AbuseCVE is built on a distributed, service-oriented architecture designed for asynchronous data processing and real-time visualization. The system relies on a decoupled design where data ingestion, processing, and serving are handled by independent components managed via Docker Compose. The technology stack incorporates a React-based frontend, a Python FastAPI backend, Celery distributed task queues, PostgreSQL for persistent storage, and Redis for both message brokering and ephemeral state management.

## Project Directory Structure

The repository is organized into distinct functional layers to maintain a clean separation of concerns across the full stack.

At the root level, the **docker-compose.yml** file defines the multi-container orchestration, while **abusecve_filters.yaml** serves as the primary configuration file for defining vulnerability matching logic. The **.env.example** provides a template for all required environmental variables.

The **backend/** directory contains the Python core of the application. Inside **app/api/**, individual route modules handle specific functional areas such as CVE retrieval, alert management, and system logs. The **app/engine/** directory houses the critical processing logic, including the pipeline orchestrator, the filtering engine, and specialized source connectors for NVD, CISA, MITRE, and RedHat. The **app/models/** directory defines the database schema using SQLAlchemy, while **app/tasks/** contains the Celery task definitions for background processing. External integrations like SMTP and Webhook handlers are located in **app/services/**.

The **frontend/** directory houses the React application. The **src/pages/** directory contains the primary view components for the dashboard, database exploration, and configuration management. API interaction logic is centralized in **src/api.js** to ensure consistent communication with the backend service.

The **nginx/** directory contains the configuration files for the reverse proxy, managing the routing of traffic between the frontend assets and the backend API service.

## Core Components

The application is logically divided into several functional containers.

The **Nginx Reverse Proxy** serves as the primary entry point for all external traffic. It listens on standard HTTP ports and routes incoming requests based on the URL path. API requests are seamlessly forwarded to the backend service, while static asset requests and standard user navigation are directed to the frontend container.

The **Frontend Interface** is a Single Page Application constructed with React and Vite. It provides the user interface for monitoring health reports, managing filter rules, reviewing queued logs, and exploring the CVE database. The interface communicates exclusively with the backend API via asynchronous HTTP requests.

The **Backend API Services** form the core logic application layer, implemented using FastAPI. This service handles user authentication, RESTful endpoint routing, configuration management via Pydantic, and direct interactions with the PostgreSQL database using SQLAlchemy asynchronous sessions. It is responsible for serving data to the frontend and providing manual execution triggers for administrative tasks.

The **Celery Worker Network** handles all heavy lifting and long-running background tasks. It consists of two sub-services: a Beat scheduler and execution Workers. These services are independent of the API layer, ensuring that web requests remain fast and responsive while network-bound tasks like fetching upstream CVE data or sending SMTP alerts are processed asynchronously in the background.

The **PostgreSQL Relational Database** provides persistent storage for all system state. This includes normalized CVE records, active filter rules, administrative logs, generated knowledge articles, and system health reports.

The **Redis In-Memory Store** performs a dual role within the architecture. Firstly, it acts as the message broker for the Celery worker network, managing task queues and result backends. Secondly, it functions as a high-throughput, temporary staging pool for raw CVE data during the ingestion pipeline, acting as a buffer between external APIs and internal database transactions.

## Data Processing Pipeline

The core functionality of AbuseCVE revolves around its continuous data ingestion and processing pipeline. This pipeline orchestrates the flow of vulnerability information from upstream providers to end-user notifications.

During the **Data Ingestion** or Fetch stage, the system reaches out to multiple authoritative sources including the National Vulnerability Database (NVD), CISA Known Exploited Vulnerabilities (KEV) catalog, MITRE CVE List, and RedHat security advisories. The system normalizes the disparate JSON schemas from these providers into a standardized internal data structure.

Once fetched, the records enter the **Log Aggregation** or Pool stage. To prevent memory exhaustion and manage the disparity between network speeds and database write speeds, normalized records are serialized and pushed into a dedicated Redis list. This creates a resilient queue that can be processed at a controlled rate.

The pipeline then transitions to the **Rule Evaluation** or Filter stage. Worker processes continuously pop records from the Redis pool. Each record is evaluated against a set of user-defined filter rules loaded from the system configuration. These rules apply pattern matching and threshold checks against attributes like severity, product name, or CVSS score.

Following evaluation, the system executes **Deduplication and Storage**. Every record, regardless of whether it matched a filter rule, is checked against the PostgreSQL database to determine if it is a new vulnerability or an update to an existing one. Updates modify existing records, while new entries are inserted. This ensures the local database remains a comprehensive mirror of upstream sources.

Finally, the **Dispatch and Alerting** stage takes over. For any new CVE record that successfully triggered a filter rule during the evaluation stage, the system queues a notification task. This typically results in an SMTP email alert being dispatched to configured recipients, detailing the vulnerability and the specific rule that flagged it.

## Worker Technical Operations

The background processing system relies heavily on Celery for task distribution and execution.

The Celery Beat container acts as the master clock. It reads the schedule configuration and periodically pushes task signatures onto the Redis message queue. For example, the primary CVE scanning cycle is initiated by the Beat scheduler at regular intervals defined by the environment configuration. Similarly, daily system health reports are scheduled to trigger at specific times.

The Celery Worker containers listen to the Redis queue for incoming task signatures. Upon receiving a task, a worker allocates a subprocess to execute the Python function. The workers are configured to gracefully restart after processing a set number of tasks or exceeding specific memory limits, mitigating potential memory leaks during massive data processing runs. Task execution lifecycle events, including starts, successes, failures, and retries, are captured via Celery signals and written back to the PostgreSQL database for administrative auditing.

## Component Communication Flow

Communication between the isolated Docker containers happens entirely over the internal Docker bridge network.

External users interact exclusively with the Nginx proxy via HTTP. Nginx terminates the connection and proxies API calls to the backend container over port 8000. 

The backend API and Celery workers communicate with the PostgreSQL database over port 5432 using the asyncpg driver, executing SQL transactions to read and write persistent data.

The connection between the application code and the background workers is mediated entirely by Redis over port 6379. When the backend needs to trigger a manual scan, it pushes a task message to Redis. The workers continuously poll Redis for these messages. Similarly, during the CVE pipeline execution, workers push raw fetched data into a specific Redis key, and subsequently read from that same key during the filtering stage. The components never communicate directly with each other regarding task execution, ensuring high availability and fault tolerance.

## Filter Engine and Configuration

The filtering engine evaluates incoming vulnerabilities against criteria defined in a YAML configuration file. When the application starts, or when a worker initializes, this file is loaded into memory. 

Rules can specify boolean logic and exact string matches. If a rule specifies a target severity level, the engine compares the incoming CVE's calculated severity against the threshold. If a rule targets specific products or vendors, the engine inspects the Common Platform Enumeration (CPE) strings attached to the CVE. If an incoming vulnerability meets all defined parameters within a single rule block, it is flagged as a match and marked for subsequent alerting.

General system configuration is managed through environment variables injected via a standard env file. This covers database credentials, API keys for external services, SMTP server details for alerting, and operational parameters like scan frequency intervals. The Pydantic settings module validates these variables at runtime, ensuring the application halts early if critical configuration details are malformed or missing.

## Deployment and Setup Guide



Deploying AbuseCVE involves orchestrating the service containers using Docker Compose and performing an initial data synchronization to populate the local CVE database.



### Prerequisites

The system requires a Linux-based host with **Docker** and the **Docker Compose** plugin installed. Ensure the host has at least 4GB of RAM to handle the intensive initial data processing tasks.



### Initial Configuration

Before starting the services, you must configure the environment variables.



1. Create a local environment file from the provided template:

   ```bash

   cp .env.example .env

   ```

2. Open the `.env` file and update the following critical parameters:

   - **POSTGRES_PASSWORD**: Set a strong password for the database.

   - **DATABASE_URL**: Update the password within the connection string to match `POSTGRES_PASSWORD`.

   - **NVD_API_KEY**: Obtain an API key from the NVD website to avoid aggressive rate limiting during the initial sync.

   - **SMTP_HOST/USER/PASSWORD**: Configure your mail server details to enable automated alerts.

   - **ALERT_RECIPIENTS**: Provide a comma-separated list of email addresses for alert delivery.



### Launching Services

Start the entire stack in detached mode using Docker Compose:



```bash

docker-compose up -d

```



This command initializes the PostgreSQL database, starts the Redis broker, launches the FastAPI backend, starts the Celery workers and scheduler, and serves the frontend through Nginx. You can verify the status of all containers using `docker-compose ps`.



### Database Initialization

Upon first launch, the local database will be empty. You must perform a one-time historical synchronization. Access the dashboard at `http://localhost` and navigate to the **Database Initialization** section.



There are three primary modes for initialization:

- **API Mode (Recommended)**: Fetches historical records directly from NVD, CISA KEV, and RedHat. This is the simplest method but can take several hours depending on NVD rate limits.

- **Local Directory Mode**: If you have a local clone of the MITRE `cvelistV5` repository, you can provide the path to the `cves/` directory. This is significantly faster for importing MITRE data.

- **Upload Mode**: Allows you to upload a ZIP archive of the MITRE `cves/` directory directly through the web interface.



### Verification and Testing

Once initialized, navigate to the **Test Chain** page in the UI. This utility allows you to execute end-to-end validation of the system:

1. **SMTP Connection**: Sends a test email to verify your mail server configuration.

2. **CVE Fetching**: Validates connectivity to upstream providers.

3. **Filter Engine**: Checks your current `abusecve_filters.yaml` logic against recent data.

4. **Full Pipeline**: Executes a complete fetch-filter-dedup cycle to ensure all components are communicating correctly.



### Accessing the Interface

- **Web UI**: Accessible at `http://localhost` (default port 80).

- **API Documentation**: Interactive Swagger documentation is available at `http://localhost/docs`.

- **System Logs**: Worker execution logs can be monitored directly in the **Logs** section of the web interface or via `docker-compose logs -f worker`.
