<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>

<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Stock Management Screen</title>
</head>
<body>
	<div align="center">
		<table border="1">
			<th>Name</th>
			<th>Code</th>
			<th>Charts</th>
			<th>Bonus/Split</th>
			<th>Delete</th>

			<c:forEach var="stock" items="${listStock}">
				<tr>

					<td>${stock.name}</td>
					<td>${stock.code}</td>
					<td>
					<a href="charts/monthlyChart?type=DP&stockId=${stock.id}&interval=30">DP</a>&nbsp;&nbsp;&nbsp;&nbsp;
                    <a href="charts/monthlyChart?type=P&stockId=${stock.id}&interval=30">P</a>&nbsp;&nbsp;&nbsp;&nbsp;
                    <a href="charts/monthlyChart?type=V&stockId=${stock.id}&interval=30">V</a>&nbsp;&nbsp;&nbsp;&nbsp;
                    <a href="charts/monthlyChart?type=OI&stockId=${stock.id}&interval=30">OI</a>&nbsp;&nbsp;&nbsp;&nbsp;
                    <a href="charts/monthlyChart?type=PCR&stockId=${stock.id}&interval=30">PCR</a>&nbsp;&nbsp;&nbsp;&nbsp;
                    <a href="charts/monthlyAvgChart?stockId=${stock.id}&interval=30">AVG</a>
                    </td>
                    <td><a href="newBonusAndSplit?id=${stock.id}">Click</a></td>
                    <td><a href="deleteStock?id=${stock.id}">Delete</a></td>
				</tr>
			</c:forEach>
		</table>
		<h4>
			New Stock Register <a href="newStock">here</a>
		</h4>
	</div>
</body>
</html>