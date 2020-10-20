
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
    "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<title>New/Edit Attribute</title>
	<style>
		.error {color:red}
	</style>
</head>
<body>
    <div align="center">
        <h1>New/Edit Attribute</h1>
        <form:form action="save" method="post" modelAttribute="attr">
        <table>
            <form:hidden path="id"/>
            <tr>
                <td>Name:</td>
                <td><form:input path="name" /></td>
            </tr>
             <tr>
                <td>Type:</td>
                <td><form:select path="type">
                    <form:options items="${attr_type}" />
                </form:select>
                </td>
            </tr>
            <tr>
            <td>Default Value:</td>
            <td><form:input path="defaultValue" />
                		<form:errors path="defaultValue" cssClass="error" />
            </td>
            </tr>
            <tr>
                <td colspan="2" align="center"><input type="submit" value="Save"></td>
            </tr>
        </table>
        </form:form>
    </div>
</body>
</html>