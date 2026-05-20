import { Card, Flex, Typography } from 'antd';

const { Text, Title } = Typography;

function renderTitle(title, subtitle, titleLevel) {
  if (title === null || title === undefined) {
    return subtitle ? <Text type="secondary">{subtitle}</Text> : null;
  }

  if (typeof title === 'string' || typeof title === 'number') {
    return (
      <Flex vertical gap={4} style={{ paddingBlock: 2 }}>
        <Title level={titleLevel} style={{ margin: 0 }}>
          {title}
        </Title>
        {subtitle ? <Text type="secondary">{subtitle}</Text> : null}
      </Flex>
    );
  }

  if (!subtitle) {
    return title;
  }

  return (
    <Flex vertical gap={4}>
      {title}
      <Text type="secondary">{subtitle}</Text>
    </Flex>
  );
}

export function AppCard({
  title,
  subtitle,
  extra,
  titleLevel,
  bodyGap,
  headerPaddingBlock,
  stickyTop,
  headerStyle,
  bodyStyle,
  style,
  styles,
  size,
  children,
  ...props
}) {
  const resolvedTitleLevel = titleLevel ?? (size === 'small' ? 5 : 4);
  const resolvedBodyGap = bodyGap ?? (size === 'small' ? 12 : 16);
  const resolvedHeaderPaddingBlock = headerPaddingBlock ?? (size === 'small' ? 14 : 18);
  const renderedTitle = renderTitle(title, subtitle, resolvedTitleLevel);

  return (
    <Card
      {...props}
      size={size}
      title={renderedTitle}
      extra={extra}
      style={{
        ...(stickyTop !== undefined && stickyTop !== null ? { position: 'sticky', top: stickyTop } : {}),
        ...style,
      }}
      styles={{
        ...styles,
        header: {
          paddingBlock: resolvedHeaderPaddingBlock,
          alignItems: 'center',
          ...headerStyle,
          ...styles?.header,
        },
        body: {
          display: 'flex',
          flexDirection: 'column',
          gap: resolvedBodyGap,
          ...bodyStyle,
          ...styles?.body,
        },
      }}
    >
      {children}
    </Card>
  );
}
