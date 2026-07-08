import React, { useState } from 'react';
import type { EmailHeader, Hop } from '../../types';
import { Copy, Check, EyeOff } from 'lucide-react';
import './EmailSummary.css';

interface EmailSummaryProps {
  header: EmailHeader;
  hops?: Hop[];
  duplicateHeaders?: string[];
}

interface FieldRowProps {
  label: string;
  value: string;
  mono?: boolean;
  redacted?: boolean;
  provider?: string;
  dim?: boolean;
}

const FieldRow: React.FC<FieldRowProps> = ({ label, value, mono, redacted, provider, dim }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (value && !redacted) {
      navigator.clipboard.writeText(value).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }).catch(() => {});
    }
  };

  const displayValue = redacted
    ? `Hidden by ${provider || 'Provider'}`
    : (value || '—');

  if (!value && !redacted) return null;

  return (
    <tr>
      <td className="email-property-label">{label}</td>
      <td className={`email-property-value ${dim ? 'email-field-dim' : ''} ${mono ? 'font-mono' : ''}`}>
        {redacted ? (
          <span className="email-redacted">
            <EyeOff size={12} style={{ marginRight: '6px' }} />
            {displayValue}
          </span>
        ) : (
          <>
            <span>{displayValue}</span>
            {!redacted && value && (
              <button className="email-copy-btn" onClick={handleCopy} title={`Copy ${label}`}>
                {copied ? <Check size={12} color="var(--success)" /> : <Copy size={12} />}
              </button>
            )}
          </>
        )}
      </td>
    </tr>
  );
};

const EmailSummary: React.FC<EmailSummaryProps> = ({ header, hops, duplicateHeaders }) => {
  const safeHops = hops ?? header.hops ?? [];
  const safeDuplicates = duplicateHeaders ?? header.duplicate_headers ?? [];

  return (
    <div className="email-summary">
      <table className="email-property-table">
        <tbody>
          <FieldRow label="Subject" value={header.subject} />
          <FieldRow label="From" value={header.from_address} />
          {header.display_name && <FieldRow label="Display Name" value={header.display_name} />}
          <FieldRow label="Sender Domain" value={header.from_domain} mono />
          <FieldRow label="To" value={header.to_address} />
          {header.cc_address && <FieldRow label="CC" value={header.cc_address} />}
          <FieldRow label="Date" value={header.date} />
          {header.reply_to && <FieldRow label="Reply-To" value={header.reply_to} />}
          {header.return_path && <FieldRow label="Return-Path" value={header.return_path} mono />}
          <FieldRow label="Message-ID" value={header.message_id} mono dim />
          {header.ip_is_hidden ? (
            <FieldRow label="Originating IP" value="" redacted provider={header.ip_provider} />
          ) : (
            <FieldRow label="Originating IP" value={header.originating_ip || ''} mono />
          )}
        </tbody>
      </table>

      <div className="email-meta-footer">
        <span>{header.header_count || 0} headers parsed</span>
        <span>•</span>
        <span>{safeHops.length} hops</span>
        {safeDuplicates.length > 0 && (
          <>
            <span>•</span>
            <span className="email-meta-dup">⚠ {safeDuplicates.length} duplicates</span>
          </>
        )}
      </div>
    </div>
  );
};

export default EmailSummary;
