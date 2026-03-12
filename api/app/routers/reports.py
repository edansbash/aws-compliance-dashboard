"""API endpoints for report generation."""

from uuid import UUID
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import Report
from app.models.report import ReportType, ReportFormat, ReportStatus
from app.schemas.report import (
    ReportCreate,
    ReportResponse,
    ReportListResponse,
)
from app.services.report_generator import (
    generate_excel_report,
    generate_pdf_dashboard,
)

router = APIRouter()


@router.post("", response_model=ReportResponse)
async def create_report(
    report_request: ReportCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a new report.

    Report types:
    - DASHBOARD_PDF: PDF summary of compliance dashboard
    - FINDINGS_EXCEL: Excel export of all findings
    """
    # Determine format based on report type
    if report_request.report_type == ReportType.DASHBOARD_PDF:
        report_format = ReportFormat.PDF
    elif report_request.report_type == ReportType.FINDINGS_EXCEL:
        report_format = ReportFormat.EXCEL
    else:
        report_format = ReportFormat.PDF

    # Create report record
    report = Report(
        report_type=report_request.report_type.value,
        format=report_format.value,
        status=ReportStatus.GENERATING.value,
        scan_id=report_request.scan_id,
        filters=report_request.filters.model_dump() if report_request.filters else None,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    try:
        filters = report_request.filters.model_dump() if report_request.filters else None

        if report_request.report_type == ReportType.DASHBOARD_PDF:
            file_bytes, filename = await generate_pdf_dashboard(
                db,
                scan_id=report_request.scan_id,
                filters=filters,
            )
        elif report_request.report_type == ReportType.FINDINGS_EXCEL:
            file_bytes, filename = await generate_excel_report(
                db,
                scan_id=report_request.scan_id,
                filters=filters,
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported report type")

        # Update report record
        report.status = ReportStatus.COMPLETED.value
        report.file_path = filename
        report.file_size = len(file_bytes)
        report.completed_at = datetime.utcnow()
        await db.commit()
        await db.refresh(report)

    except Exception as e:
        report.status = ReportStatus.FAILED.value
        report.error_message = str(e)[:1000]
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

    return report


@router.get("", response_model=ReportListResponse)
async def list_reports(
    page: int = 1,
    per_page: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """List all generated reports."""
    offset = (page - 1) * per_page

    query = (
        select(Report)
        .order_by(Report.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )

    result = await db.execute(query)
    reports = result.scalars().all()

    # Get total count
    count_result = await db.execute(select(Report))
    total = len(count_result.scalars().all())

    return ReportListResponse(
        items=reports,
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page if total > 0 else 1,
    )


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get report metadata."""
    result = await db.execute(
        select(Report).where(Report.id == report_id)
    )
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return report


@router.get("/{report_id}/download")
async def download_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Download a generated report file."""
    result = await db.execute(
        select(Report).where(Report.id == report_id)
    )
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.status != ReportStatus.COMPLETED.value:
        raise HTTPException(status_code=400, detail="Report is not ready for download")

    # Regenerate the report (in production, you'd store and retrieve from storage)
    filters = report.filters

    try:
        if report.report_type == ReportType.DASHBOARD_PDF.value:
            file_bytes, filename = await generate_pdf_dashboard(
                db,
                scan_id=report.scan_id,
                filters=filters,
            )
            media_type = "application/pdf"
        elif report.report_type == ReportType.FINDINGS_EXCEL.value:
            file_bytes, filename = await generate_excel_report(
                db,
                scan_id=report.scan_id,
                filters=filters,
            )
            media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        else:
            raise HTTPException(status_code=400, detail="Unsupported report type")

        return Response(
            content=file_bytes,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
            },
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")


@router.delete("/{report_id}")
async def delete_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a report record."""
    result = await db.execute(
        select(Report).where(Report.id == report_id)
    )
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    await db.delete(report)
    await db.commit()

    return {"message": "Report deleted"}


@router.post("/generate/dashboard-pdf")
async def generate_dashboard_pdf_direct(
    scan_id: Optional[UUID] = None,
    account_ids: Optional[str] = Query(None, description="Comma-separated account IDs"),
    regions: Optional[str] = Query(None, description="Comma-separated regions"),
    severities: Optional[str] = Query(None, description="Comma-separated severities"),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate and directly download a PDF dashboard report.

    This is a convenience endpoint that generates and returns the PDF in one request.
    """
    filters = {}
    if account_ids:
        filters["account_ids"] = [a.strip() for a in account_ids.split(",")]
    if regions:
        filters["regions"] = [r.strip() for r in regions.split(",")]
    if severities:
        filters["severities"] = [s.strip() for s in severities.split(",")]

    try:
        file_bytes, filename = await generate_pdf_dashboard(
            db,
            scan_id=scan_id,
            filters=filters if filters else None,
        )

        return Response(
            content=file_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
            },
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")


@router.post("/generate/findings-excel")
async def generate_findings_excel_direct(
    scan_id: Optional[UUID] = None,
    account_ids: Optional[str] = Query(None, description="Comma-separated account IDs"),
    regions: Optional[str] = Query(None, description="Comma-separated regions"),
    severities: Optional[str] = Query(None, description="Comma-separated severities"),
    statuses: Optional[str] = Query(None, description="Comma-separated statuses"),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate and directly download an Excel findings report.

    This is a convenience endpoint that generates and returns the Excel file in one request.
    """
    filters = {}
    if account_ids:
        filters["account_ids"] = [a.strip() for a in account_ids.split(",")]
    if regions:
        filters["regions"] = [r.strip() for r in regions.split(",")]
    if severities:
        filters["severities"] = [s.strip() for s in severities.split(",")]
    if statuses:
        filters["statuses"] = [s.strip() for s in statuses.split(",")]

    try:
        file_bytes, filename = await generate_excel_report(
            db,
            scan_id=scan_id,
            filters=filters if filters else None,
        )

        return Response(
            content=file_bytes,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
            },
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate Excel: {str(e)}")
